lab/rds/mysql

Armageddon Lab-1a 010426 through 010926

Steps:
1. Create VPC "armageddon_laba"
	10.155.0.0/16

	Region - us-east-1
	2 AZ:
	us-east-1a
	us-east-1b

	Public subnet CIDR us-east-1a 10.155.1.0/24
	Public subnet CIDR us-east-1b 10.155.2.0/24
	Private subnet CIDR us-east-1a 10.155.11.0/24
	Private subnet CIDR us-east-1b 10.155.12.0/24

	NAT Gateway - none
	VPC Endpoints - none (S3 Gateway not enabled)

	Enabled DNS hostnames 
	Enabled DNS resolution
	No tags created

2. Create  security group "lab_ec2_sg"
	This is for EC2 to be accessible by HTTP and SSH
	Allows IPv4 anywhere for inbound HTTP and SSH (you can limit to your IP),
	- HTTP TCP 80 Anywhere IPV4 0.0.0.0/0
	- SSH TCP 22 MyIP (68.9.108.90/32) *** ERROR found upon connecting to EC2.  SSH to MyIP did not work.  Changed SSH to Anywhere IPV4 to resolve the issue.
	- DO NOT TOUCH Outbound Rules

3. Policy & Roles to allows EC2 to get secret:
For this will create the need permissions policy first, then attach it to the role along with the proper principal,,

3a. permission policy:,
```{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadSpecificSecret",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": "arn:aws:secretsmanager:us-east-1:085089485330:lab/rds/mysql-*"
        }
    ]
}

Create Policy Name: "armageddon_laba_secretpolicy"



3b. Create Role:
	Select trusted entity = AWS Service
	Use Case = EC2
	Add permission 
		Locate created policy "armageddon_laba_secretpolicy"
	Role Name "laba_armageddon" - description "Allows EC2 instances to call AWS services on your behalf."
Trust policy:
```{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com"
                ]
            }
        }
    ]
}
Create Role.  Role name "laba_armageddon"
Role:
Trusted relationships > Trusted entities
```{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

instance profile ARN:
arn:aws:iam::085089485330:instance-profile/laba_armageddon

ARN:
arn:aws:iam::085089485330:role/laba_armageddon

4. Launch EC2 Instance
	Name: "ec2_lab_app"
	Application and OS Images = Amazon Linux 
	AMI ID = ami-068c0051b15cdb816
	Instance Type = t3.micro
	Key pair - create new = "armageddon_010726" saved to desktop
	Edit Network setting
		VPC "armageddon_laba-vpc"
		Subnet = "armageddon_laba-subnet-public1-us-east-1a"
		Auto-assign public IP = Enable
		Select existing security group = "lab_ec2_sg"
	Advanced details:
		Provide UserData Script.  Team-Dawgs made change to script to account for the need to upload MariaDB by adding below into script:
dnf install mariadb105 -y

Launched EC2 instance.
![](./lab-1a-Kuridango/Armageddon laba appendix 1.1.png)

5. Attach role to instance:
steps:
Go to Modify IAM Role via Instance > Actions > Security > Modify IAM Role
Attach the role that was just created under 'IAM Role',
click 'Update IAM Role',

![](./lab-1a-Kuridango/Armageddon laba appendix 1.2.png)

6. Create RDS Database:
Go to create database under 'Aurora and RDS',
Go 'Full Configuration',
Then "MySQL",
Then Choose 'Free Tier',
Choose DB Instance Identifier ('lab-mysql'),
Choose Master username ('admin'),
Then select 'Self Managed' for 'Credentials management',
Then create and remember your password ('ArmRDS1426'), (Password is just for test and learning purpose)
Then leave setting default until Connectivity, select "Connect to and EC2 compute resource",
Choose the created EC2 under 'EC2 Instance',
VPC should be automatically selected,
DB Subnet Group, choose automatic setup,
Public Access = 'No',
For VPC Security Group check 'Create New',
Enable Logs then 'Create Database',

![](./lab-1a-Kuridango/Armageddon laba appendix 1.3.png)
lab-mysql.ccfog8cqu1vr.us-east-1.rds.amazonaws.com
085089485330

7. Create Secret in Secrets Manager
Under Secrets Manager, select 'Store a New Secret',
'Secret Type' is Credentials for Amazon RDS Database,
Credentials, User name = 'admin',
Credentials, Password = 'ArmRDS1426', (from the one created with RDS DB)(Password is just for test and learning purpose)
Then select your created DB, then click next,
Set Secret Name to be same as in policy and application script,,
Then click until you reach review (leave configuration rotation as default),,
Review and then 'Store' your secret.,

Secret Name: lab/rds/mysql
Secret ARN: arn:aws:secretsmanager:us-east-1:085089485330:secret:lab/rds/mysql-FHyMFE

8. aws secretsmanager get-secret-value --secret-id lab/rds/mysql
6.6 Verify Secrets Manager Access (From EC2) SSH into EC2 and run: aws secretsmanager get-secret-value
--secret-id lab/rds/MySQL

Expected: JSON containing: username password host port
{
    "ARN": "arn:aws:secretsmanager:us-east-1:085089485330:secret:lab/rds/mysql-FHyMFE",
    "Name": "lab/rds/mysql",
    "VersionId": "18397649-02b4-4fcc-8dcc-506b321d5bf7",
    "SecretString": "{\"username\":\"admin\",\"password\":\"ArmRDS1426\",\"engine\":\"mysql\",\"host\":\"lab-mysql.ccfog8cqu1vr.us-east-1.rds.amazonaws.com\",\"port\":3306,\"dbInstanceIdentifier\":\"lab-mysql\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-01-06T00:24:40.393000+00:00"
}

If this fails, IAM is misconfigured. 
Was initially misconfigured,.  

Below was error message:
(AccessDeniedException) when calling the GetSecretValue operation: User: arn:aws:sts::085089485330:assumed-role/laba_armageddon/i-06e842b7968d98183 is not authorized to perform: secretsmanager:GetSecretValue on resource: lab/rds/mysql because no identity-based policy allows the secretsmanager:GetSecretValue action."

Updated permissions policy to below, Error resolved:
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "ReadOnlyListActions",
			"Effect": "Allow",
			"Action": [
				"ec2:DescribeInstances",
				"ec2:DescribeSecurityGroups",
				"rds:DescribeDBInstances"
			],
			"Resource": "*"
		},
		{
			"Sid": "ReadSpecificSecret",
			"Effect": "Allow",
			"Action": [
				"secretsmanager:GetSecretValue"
			],
			"Resource": "arn:aws:secretsmanager:us-east-1:085089485330:lab/rds/mysql*"
		}
	]
}

Verified role using "aws sts get-caller-identity"
{
    "UserId": "AROARHT52QIJACTWM24ZW:i-0fab5f2d73d2b78b8",
    "Account": "085089485330",
    "Arn": "arn:aws:sts::085089485330:assumed-role/laba_armageddon/i-0fab5f2d73d2b78b8"
}

Once confirmed secrets configuration, typed "aws secretsmanager get-secret-value --secret-id lab/rds/MySQL" in prompt.
Output below:
{
    "ARN": "arn:aws:secretsmanager:us-east-1:085089485330:secret:lab/rds/mysql-FHyMFE",
    "Name": "lab/rds/mysql",
    "VersionId": "18397649-02b4-4fcc-8dcc-506b321d5bf7",
    "SecretString": "{\"username\":\"admin\",\"password\":\"ArmRDS1426\",\"engine\":\"mysql\",\"host\":\"lab-mysql.ccfog8cqu1vr.us-east-1.rds.amazonaws.com\",\"port\":3306,\"dbInstanceIdentifier\":\"lab-mysql\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-01-06T00:24:40.393000+00:00"
}

6.7 Verify Database Connectivity (From EC2) Install MariaDB client: sudo dnf install mariadb105 -y

Once restart completed, typed "mysql -h <RDS_ENDPOINT> -u admin -p"  <RDS_ENDPOINT> = lab-mysql.ccfog8cqu1vr.us-east-1.rds.amazonaws.com 
then prompted for password:
Entered the RDS DB password and was able to access MYSQL DB.
In MYSQL prompt, type "SHOW DATABASES;
List of databases shown

Make datebase
In MYSQL prompt, type "CREATE DATEBASE labdb;"

In MYSQL prompt, type "SHOW DATABASES;"
it will show new db created in rds

![](./lab-1a-Kuridango/Armageddon laba appendix 1.5.png)


To exit MYSQL type "exit" enter

Next, type "sudo systemctl restart rdsapp" then enter


6.8 Verify Data Path End-to-End From browser: 

**http://<EC2\_PUBLIC\_IP>/init** 

**http://<EC2\_PUBLIC\_IP>/add?note=cloud_labs_are_real** 

**http://<EC2\_PUBLIC\_IP>/list**

![](./lab-1a-Kuridango/Armageddon 010726 appendix 1.6.png)
![](./lab-1a-Kuridango/Armageddon 010726 appendix 1.7.png)

##AWS CLI drills using GitBash

List all security groups in a region

    aws ec2 describe-security-groups \
      --region us-east-1 \
      --query "SecurityGroups[].{GroupId:GroupId,Name:GroupName,VpcId:VpcId}" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.1.png)

Inspect a specific security group (inbound & outbound rules)

    aws ec2 describe-security-groups \
      --group-ids sg-0a2d636263aa34738 \
      --region us-east-1 \
      --output json

![](./lab-1a-Kuridango/AWSCLI_screenshot2.2.png)

Verify which resources are using the security group
EC2 instances

    aws ec2 describe-instances \
      --filters Name=instance.group-id,Values=sg-0a2d636263aa34738 \
      --region us-east-1 \
      --query "Reservations[].Instances[].InstanceId" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.3.png)

RDS instances

    aws rds describe-db-instances \
      --region us-east-1 \
      --query "DBInstances[?contains(VpcSecurityGroups[].VpcSecurityGroupId, 'sg-0a2d636263aa34738')].DBInstanceIdentifier" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.4.png)

List all RDS instances

    aws rds describe-db-instances \
      --region us-east-1 \
      --query "DBInstances[].{DB:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Vpc:DBSubnetGroup.VpcId}" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.5.png)

Inspect a specific RDS instance

    aws rds describe-db-instances \
      --db-instance-identifier lab-mysql \
      --region us-east-1 \
      --output json

![](./lab-1a-Kuridango/AWSCLI_screenshot2.6.png)

Critical checks
    "PubliclyAccessible": false
    Correct VPC
    Correct subnet group
    Correct security groups

Verify RDS security groups explicitly

    aws rds describe-db-instances \
      --db-instance-identifier lab-mysql \
      --region us-east-1 \
      --query "DBInstances[].VpcSecurityGroups[].VpcSecurityGroupId" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.7.png)

Verify RDS subnet placement

    aws rds describe-db-subnet-groups \
      --region us-east-1 \
      --query "DBSubnetGroups[].{Name:DBSubnetGroupName,Vpc:VpcId,Subnets:Subnets[].SubnetIdentifier}" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.8.png)

What you’re verifying
    Private subnets only
    No IGW route
    Correct AZ spread

Verify Network Exposure (Fast Sanity Checks)
Check if RDS is publicly reachable (quick flag)

    aws rds describe-db-instances \
      --db-instance-identifier lab-mysql \
      --region us-east-1 \
      --query "DBInstances[].PubliclyAccessible" \
      --output text

![](./lab-1a-Kuridango/AWSCLI_screenshot2.9.png)

Expected output: false
Verify Secrets Manager (Existence, Metadata, Access)

    aws secretsmanager list-secrets \
      --region us-east-1 \
      --query "SecretList[].{Name:Name,ARN:ARN,Rotation:RotationEnabled}" \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.10.png)

What you’re verifying
    Secret exists
    Rotation state is known
    Naming is intentional

Describe a specific secret (NO value exposure)

    aws secretsmanager describe-secret \
      --secret-id lab/rds/mysql \
      --region us-east-1 \
      --output json

![](./lab-1a-Kuridango/AWSCLI_screenshot2.11.png)

Key fields to check
    RotationEnabled
    KmsKeyId
    LastChangedDate
    LastAccessedDate
Verify which IAM principals can access the secret

    aws secretsmanager get-resource-policy \
      --secret-id lab/rds/mysql \
      --region us-east-1 \
      --output json

![](./lab-1a-Kuridango/AWSCLI_screenshot2.12.png)

What you’re verifying
    Only expected roles are listed
    No wildcard principals
    No cross-account access unless justified

Verify IAM Role Attached to an EC2 Instance
  Step 1: Identify the EC2 instance

    aws ec2 describe-instances \
      --region us-east-1 \
      --query "Reservations[].Instances[].InstanceId" \
      --output text

![](./lab-1a-Kuridango/AWSCLI_screenshot2.13.png)

  Step 2: Check the IAM role attached to the instance

    aws ec2 describe-instances \
      --instance-ids i-0fab5f2d73d2b78b8 \
      --region us-east-1 \
      --query "Reservations[].Instances[].IamInstanceProfile.Arn" \
      --output text

![](./lab-1a-Kuridango/AWSCLI_screenshot2.14.png)

Expected: arn:aws:sts::085089485330:assumed-role/laba_armageddon

If empty → no role attached (this is a finding).

  Step 3: Resolve instance profile → role name

    aws iam get-instance-profile \
      --instance-profile-name laba_armageddon \
      --query "InstanceProfile.Roles[].RoleName" \
      --output text

![](./lab-1a-Kuridango/AWSCLI_screenshot2.15.png)


Verify IAM Role Permissions (Critical)
List policies attached to the role

    aws iam list-attached-role-policies \
      --role-name laba_armageddon \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.16.png)

List inline policies (often forgotten)

    aws iam list-role-policies \
      --role-name laba_armageddon \
      --output table

![](./lab-1a-Kuridango/AWSCLI_screenshot2.17.png)

Inspect a specific managed policy

    aws iam get-policy-version \
      --policy-arn arn:aws:iam::085089485330:policy/armageddon_laba_secretpolicy \
      --version-id v1 \
      --output json

![](./lab-1a-Kuridango/AWSCLI_screenshot2.18.png)

What you’re verifying
    Least privilege
    Only secretsmanager:GetSecretValue if read-only
    No wildcard * unless justified
Verify EC2 → RDS access path (security-group–to–security-group)

    aws ec2 describe-security-groups \
      --group-ids sg-0a2d636263aa34738 \
      --region us-east-1 \
      --query "SecurityGroups[].IpPermissions"

![](./lab-1a-Kuridango/AWSCLI_screenshot2.19.png)

    aws secretsmanager describe-secret \
      --secret-id lab/rds/mysql \
      --region us-east-1

![](./lab-1a-Kuridango/AWSCLI_screenshot2.20.png)

If this works:
    IAM role is correctly attached
    Permissions are effective

Student Deliverables:
1) Screenshot of:
  RDS SG inbound rule using source = lab_ec2_sg
    ![](./lab-1a-Kuridango/Armageddon_Student_Deliverables1.png)
  EC2 role attached
    ![](./lab-1a-Kuridango/Armageddon laba appendix 1.2.png)
  /list output showing at least 3 notes
    ![](./lab-1a-Kuridango/EC2_Public_IP_Notes_List.png)

2) Short answers:
  A) Why is DB inbound source restricted to the EC2 security group? 
    Instance can go down at anytime and EC2 instance website can reboot with new IP address and connection would break.  It is better with Security Group as it is stateful.  
  B) What port does MySQL use? 
    3306
  C) Why is Secrets Manager better than storing creds in code/user-data? 
    Security Manager can handle key rotation and it is easy integration.

3) Evidence for Audits / Labs (Recommended Output)

      aws ec2 describe-security-groups --group-ids sg-0a2d636263aa34738 > sg.json
      aws rds describe-db-instances --db-instance-identifier lab-mysql > rds.json
      aws secretsmanager describe-secret --secret-id lab/rds/mysql > secret.json
      aws ec2 describe-instances --instance-ids i-0fab5f2d73d2b78b8 > instance.json
      aws iam list-attached-role-policies --role-name laba_armageddon > role-policies.json


```kurid@LAPTOP-E6UU0OED MINGW64 ~/documents/theowaf/class7/aws/armageddon
$ aws ec2 describe-security-groups --group-ids sg-0a2d636263aa34738
{
    "SecurityGroups": [
        {
            "GroupId": "sg-0a2d636263aa34738",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": []
                }
            ],
            "VpcId": "vpc-0b72cdb249313482b",
            "SecurityGroupArn": "arn:aws:ec2:us-east-1:085089485330:security-group/sg-0a2d636263aa34738",
            "OwnerId": "085089485330",
            "GroupName": "lab_ec2_sg",
            "Description": "Allows access to ec2 instance",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": []
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": []
                }
            ]
        }
    ]
}


kurid@LAPTOP-E6UU0OED MINGW64 ~/documents/theowaf/class7/aws/armageddon
$ aws rds describe-db-instances --db-instance-identifier lab-mysql
{
    "DBInstances": [
        {
            "DBInstanceIdentifier": "lab-mysql",
            "DBInstanceClass": "db.t4g.micro",
            "Engine": "mysql",
            "DBInstanceStatus": "available",
            "MasterUsername": "admin",
            "Endpoint": {
                "Address": "lab-mysql.ccfog8cqu1vr.us-east-1.rds.amazonaws.com",                "Port": 3306,
                "HostedZoneId": "Z2R2ITUGPM61AM"
            },
            "AllocatedStorage": 400,
            "InstanceCreateTime": "2026-01-09T23:36:21.383000+00:00",
            "PreferredBackupWindow": "07:10-07:40",
            "BackupRetentionPeriod": 1,
            "DBSecurityGroups": [],
            "VpcSecurityGroups": [
                {
                    "VpcSecurityGroupId": "sg-06e6dac112af226c0",
                    "Status": "active"
                }
            ],
            "DBParameterGroups": [
                {
                    "DBParameterGroupName": "default.mysql8.0",
                    "ParameterApplyStatus": "in-sync"
                }
            ],
            "AvailabilityZone": "us-east-1a",
            "DBSubnetGroup": {
                "DBSubnetGroupName": "rds-ec2-db-subnet-group-3",
                "DBSubnetGroupDescription": "Created from the RDS Management Console",
                "VpcId": "vpc-0b72cdb249313482b",
                "SubnetGroupStatus": "Complete",
                "Subnets": [
                    {
                        "SubnetIdentifier": "subnet-08a2196ab8fb111b3",
                        "SubnetAvailabilityZone": {
                            "Name": "us-east-1a"
                        },
                        "SubnetOutpost": {},
                        "SubnetStatus": "Active"
                    },
                    {
                        "SubnetIdentifier": "subnet-085f3999fe3182e59",
                        "SubnetAvailabilityZone": {
                            "Name": "us-east-1f"
                        },
                        "SubnetOutpost": {},
                        "SubnetStatus": "Active"
                    },
                    {
                        "SubnetIdentifier": "subnet-0dd439bf89e89ee7d",
                        "SubnetAvailabilityZone": {
                            "Name": "us-east-1d"
                        },
                        "SubnetOutpost": {},
                        "SubnetStatus": "Active"
                    },
                    {
                        "SubnetIdentifier": "subnet-09ecc806e2e693005",
                        "SubnetAvailabilityZone": {
                            "Name": "us-east-1e"
                        },
                        "SubnetOutpost": {},
                        "SubnetStatus": "Active"
                    },
                    {
                        "SubnetIdentifier": "subnet-07189ba28095eeea9",
                        "SubnetAvailabilityZone": {
                            "Name": "us-east-1b"
                        },
                        "SubnetOutpost": {},
                        "SubnetStatus": "Active"
                    }
                ]
            },
            "PreferredMaintenanceWindow": "wed:03:23-wed:03:53",
            "PendingModifiedValues": {},
            "LatestRestorableTime": "2026-01-10T02:40:00+00:00",
            "MultiAZ": false,
            "EngineVersion": "8.0.43",
            "AutoMinorVersionUpgrade": true,
            "ReadReplicaDBInstanceIdentifiers": [],
            "LicenseModel": "general-public-license",
            "OptionGroupMemberships": [
                {
                    "OptionGroupName": "default:mysql-8-0",
                    "Status": "in-sync"
                }
            ],
            "PubliclyAccessible": false,
            "StorageType": "gp2",
            "DbInstancePort": 0,
            "StorageEncrypted": true,
            "KmsKeyId": "arn:aws:kms:us-east-1:085089485330:key/712cd65b-4955-4cc9-8adb-0642cee39faf",
            "DbiResourceId": "db-ZAVIXBWNE6IB5AV356J32JSE4A",
            "CACertificateIdentifier": "rds-ca-rsa2048-g1",
            "DomainMemberships": [],
            "CopyTagsToSnapshot": true,
            "MonitoringInterval": 0,
            "DBInstanceArn": "arn:aws:rds:us-east-1:085089485330:db:lab-mysql",
            "IAMDatabaseAuthenticationEnabled": false,
            "DatabaseInsightsMode": "standard",
            "PerformanceInsightsEnabled": false,
            "EnabledCloudwatchLogsExports": [
                "audit",
                "error",
                "general",
                "iam-db-auth-error",
                "slowquery"
            ],
            "DeletionProtection": false,
            "AssociatedRoles": [],
            "MaxAllocatedStorage": 1000,
            "TagList": [],
            "CustomerOwnedIpEnabled": false,
            "ActivityStreamStatus": "stopped",
            "BackupTarget": "region",
            "NetworkType": "IPV4",
            "StorageThroughput": 0,
            "CertificateDetails": {
                "CAIdentifier": "rds-ca-rsa2048-g1",
                "ValidTill": "2027-01-09T23:35:03+00:00"
            },
            "DedicatedLogVolume": false,
            "IsStorageConfigUpgradeAvailable": false,
            "EngineLifecycleSupport": "open-source-rds-extended-support-disabled"
        }
    ]
}


kurid@LAPTOP-E6UU0OED MINGW64 ~/documents/theowaf/class7/aws/armageddon
$ aws secretsmanager describe-secret --secret-id lab/rds/mysql
{
    "ARN": "arn:aws:secretsmanager:us-east-1:085089485330:secret:lab/rds/mysql-FHyMFE",
    "Name": "lab/rds/mysql",
    "LastChangedDate": "2026-01-05T19:24:40.398000-05:00",
    "LastAccessedDate": "2026-01-09T19:00:00-05:00",
    "Tags": [],
    "VersionIdsToStages": {
        "18397649-02b4-4fcc-8dcc-506b321d5bf7": [
            "AWSCURRENT"
        ]
    },
    "CreatedDate": "2026-01-05T19:24:40.360000-05:00"
}


kurid@LAPTOP-E6UU0OED MINGW64 ~/documents/theowaf/class7/aws/armageddon
$ aws ec2 describe-instances --instance-ids i-0fab5f2d73d2b78b8
{
    "Reservations": [
        {
            "ReservationId": "r-0f78c8d631cb646b9",
            "OwnerId": "085089485330",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "AttachTime": "2026-01-09T23:27:00+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-08a4d9675630f0b33"
                            }
                        }
                    ],
                    "ClientToken": "703cea2b-c3cf-4ddf-811a-e2743c932a79",
                    "EbsOptimized": true,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::085089485330:instance-profile/laba_armageddon",
                        "Id": "AIPARHT52QIJIM5XKE3SN"
                    },
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-18-212-109-220.compute-1.amazonaws.com",
                                "PublicIp": "18.212.109.220"
                            },
                            "Attachment": {
                                "AttachTime": "2026-01-09T23:26:59+00:00",
                                "AttachmentId": "eni-attach-06660f1e981cf62c6",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupId": "sg-0a2d636263aa34738",
                                    "GroupName": "lab_ec2_sg"
                                },
                                {
                                    "GroupId": "sg-0c47e71f980b48d1a",
                                    "GroupName": "ec2-rds-1"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "0e:b0:be:b7:12:b3",
                            "NetworkInterfaceId": "eni-084eeaccd42932a1c",
                            "OwnerId": "085089485330",
                            "PrivateDnsName": "ip-10-155-1-153.ec2.internal",
                            "PrivateIpAddress": "10.155.1.153",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-18-212-109-220.compute-1.amazonaws.com",
                                        "PublicIp": "18.212.109.220"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-10-155-1-153.ec2.internal",
                                    "PrivateIpAddress": "10.155.1.153"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-06295b7d0037f5338",
                            "VpcId": "vpc-0b72cdb249313482b",
                            "InterfaceType": "interface",
                            "Operator": {
                                "Managed": false
                            }
                        }
                    ],
                    "RootDeviceName": "/dev/xvda",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0a2d636263aa34738",
                            "GroupName": "lab_ec2_sg"
                        },
                        {
                            "GroupId": "sg-0c47e71f980b48d1a",
                            "GroupName": "ec2-rds-1"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "ec2_lab_app"
                        }
                    ],
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 2
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 2,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "BootMode": "uefi-preferred",
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2026-01-09T23:26:59+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default",
                        "RebootMigration": "default"
                    },
                    "CurrentInstanceBootMode": "uefi",
                    "NetworkPerformanceOptions": {
                        "BandwidthWeighting": "default"
                    },
                    "Operator": {
                        "Managed": false
                    },
                    "InstanceId": "i-0fab5f2d73d2b78b8",
                    "ImageId": "ami-07ff62358b87c7116",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "PrivateDnsName": "ip-10-155-1-153.ec2.internal",
                    "PublicDnsName": "ec2-18-212-109-220.compute-1.amazonaws.com",
                    "StateTransitionReason": "",
                    "KeyName": "armageddon_010726",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t3.micro",
                    "LaunchTime": "2026-01-09T23:26:59+00:00",
                    "Placement": {
                        "AvailabilityZoneId": "use1-az6",
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-east-1a"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "SubnetId": "subnet-06295b7d0037f5338",
                    "VpcId": "vpc-0b72cdb249313482b",
                    "PrivateIpAddress": "10.155.1.153",
                    "PublicIpAddress": "18.212.109.220"
                }
            ]
        }
    ]
}


kurid@LAPTOP-E6UU0OED MINGW64 ~/documents/theowaf/class7/aws/armageddon
$ aws iam list-attached-role-policies --role-name laba_armageddon
{
    "AttachedPolicies": [
        {
            "PolicyName": "armageddon_laba_secretpolicy",
            "PolicyArn": "arn:aws:iam::085089485330:policy/armageddon_laba_secretpolicy"
        }
    ]
}```

Then Answer:
    Why each rule exists
        Each rule ensures who can access the database.
    What would break if removed
        Access to the database and permissions would break
    Why broader access is forbidden
        Limiting access to who needs access by establishing roles
    Why this role exists
    Why it can read this secret
    Why it cannot read others

teardown process:
1. RDS
2. EC2
3. VPC
4. Subnet groups

