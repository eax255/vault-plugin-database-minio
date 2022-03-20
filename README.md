# vault-plugin-database-minio

hashicorp vault plugin for minio

## Usage
Just normal vault database plugin, supports root credential rotation and static roles.

You can attach creation/rotation statements containing:
```
{
  "SetPolicy": ["readonly"]
}
```
to list policies to attach to dynamic/static roles.

You can also list iam policies to create directly:
```
{
  "EnsurePolicy": [
    {
      "Name": "readonly_sample",
      "Policy": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "s3:GetObject",
              "s3:GetBucketLocation"
            ],
            "Resource": [
              "arn:aws:s3:::*"
            ]
          }
        ]
      }
    }
  ]
}
```
but you probably should use proper configuration management for this.

NOTE: if you use static roles, either configure roles statically via configuration management or add `rotation_statements` to the role
