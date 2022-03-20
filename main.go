package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/helper/template"
	madmin "github.com/minio/madmin-go"
	iampolicy "github.com/minio/pkg/iam/policy"
)

const (
	defaultUsernameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName |truncate 15) (.RoleName |truncate 15) (random 20) (unix_time) | truncate 100 }}`
)

var _ dbplugin.Database = (*Minio)(nil)

type Minio struct {
	mux    sync.RWMutex
	config map[string]interface{}

	usernameProducer template.StringTemplate
}

func (minio *Minio) Type() (string, error) {
	return "minio", nil
}

func (minio *Minio) SecretValues() map[string]string {
	return map[string]string{
		"secretKey": "[SecretKey]",
		"password":  "[Password]",
	}
}

func (minio *Minio) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to retrieve username_template: %w", err)
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUsernameTemplate
	}

	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %w", err)
	}

	_, err = up.Generate(dbplugin.UsernameMetadata{})
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	for _, requiredField := range []string{"username", "password", "url"} {
		raw, ok := req.Config[requiredField]
		if !ok {
			return dbplugin.InitializeResponse{}, fmt.Errorf("%q must be provided", requiredField)
		}
		if _, ok := raw.(string); !ok {
			return dbplugin.InitializeResponse{}, fmt.Errorf("%q must be a string", requiredField)
		}
	}

	minio.mux.Lock()
	defer minio.mux.Unlock()
	minio.usernameProducer = up
	minio.config = req.Config
	resp := dbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

type EnsurePolicyStatement struct {
	Name   string
	Policy *iampolicy.Policy
}

type MinioStatement struct {
	EnsurePolicy []EnsurePolicyStatement
	SetPolicy    []string
}

func parseMinioStatement(command string) (statement MinioStatement, err error) {
	err = json.Unmarshal([]byte(command), &statement)
	return
}

func parseMinioStatements(commands dbplugin.Statements) (statements []MinioStatement, err error) {
	merr := &multierror.Error{}
	for _, command := range commands.Commands {
		statement, err := parseMinioStatement(command)
		if err == nil {
			statements = append(statements, statement)
		}
		merr = multierror.Append(merr, err)
	}
	err = merr.ErrorOrNil()
	return
}

func (minio *Minio) statementChecker(ctx context.Context, client *madmin.AdminClient, statements []MinioStatement) ([]string, error) {
	policyList := []string{}
	for _, statement := range statements {
		for _, policy := range statement.EnsurePolicy {
			if err := policy.Policy.Validate(); err != nil {
				return nil, err
			} else if byte_policy, err := json.Marshal(policy.Policy); err != nil {
				return nil, err
			} else if err := client.AddCannedPolicy(ctx, policy.Name, byte_policy); err != nil {
				return nil, err
			}
			policyList = append(policyList, policy.Name)
		}
		for _, policy := range statement.SetPolicy {
			policyList = append(policyList, policy)
		}
	}
	return policyList, nil
}

func (minio *Minio) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	minio.mux.RLock()
	defer minio.mux.RUnlock()

	username, err := minio.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	client, err := buildClient(minio.config)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	statements, err := parseMinioStatements(req.Statements)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if policyList, err := minio.statementChecker(ctx, client, statements); err != nil {
		return dbplugin.NewUserResponse{}, err
	} else if err := client.AddUser(ctx, username, req.Password); err != nil {
		return dbplugin.NewUserResponse{}, err
	} else if err := client.SetPolicy(ctx, strings.Join(policyList, ","), username, false); err != nil {
		client.RemoveUser(ctx, username)
		return dbplugin.NewUserResponse{}, err
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (minio *Minio) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	minio.mux.RLock()
	defer minio.mux.RUnlock()

	client, err := buildClient(minio.config)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	if err := client.RemoveUser(ctx, req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	return dbplugin.DeleteUserResponse{}, nil
}

func (minio *Minio) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	minio.mux.RLock()
	defer minio.mux.RUnlock()

	client, err := buildClient(minio.config)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}

	if req.Password != nil {
		if statements, err := parseMinioStatements(req.Password.Statements); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		} else if policyList, err := minio.statementChecker(ctx, client, statements); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		} else if err := client.SetUser(ctx, req.Username, req.Password.NewPassword, madmin.AccountEnabled); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		} else if len(policyList) > 0 {
			if err := client.SetPolicy(ctx, strings.Join(policyList, ","), req.Username, false); err != nil {
				return dbplugin.UpdateUserResponse{}, err
			}
		}
	}

	return dbplugin.UpdateUserResponse{}, nil
}

func (minio *Minio) Close() error {
	return nil
}

func buildClient(config map[string]interface{}) (*madmin.AdminClient, error) {
	accessKey := ""
	secretKey := ""
	nonparsed_url := ""
	for k, v := range map[string]*string{"url": &nonparsed_url, "username": &accessKey, "password": &secretKey} {
		if raw, ok := config[k]; !ok {
			return nil, fmt.Errorf("%s not found", k)
		} else if *v, ok = raw.(string); !ok {
			return nil, fmt.Errorf("%s must be a string", k)
		}
	}
	parsed_url, err := url.Parse(nonparsed_url)
	if err != nil {
		return nil, err
	}

	ssl := (parsed_url.Scheme == "https")
	return madmin.New(parsed_url.Host, accessKey, secretKey, ssl)
}

func New() (interface{}, error) {
	db := &Minio{}
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues), nil
}

func main() {
	db, err := New()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	dbplugin.Serve(db.(dbplugin.Database))
}
