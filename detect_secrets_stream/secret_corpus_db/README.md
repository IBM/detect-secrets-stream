# secret-corpus-db
repo to set-up / maintain the secret-corpus-db

The secret-corpus-db is the central store of found tokens / secrets.  Its security is paramount.  The approach for its design & maintenance is subject to scruitiny by IBM controls & is currently undergoing security testing.

This component is designed to be a generalised set of functions to perform all of the database control actions in an entirely transparent & secure way.

These include:
- Creating the Postgres users & associated access controls.
- Updating their passwords & pushing them into Key Protect.
- Creating all of the data schema & associated entities.
- Table row addition functions.
- All table querying.
- Table tear down.
- User & KP key deletion.



# gd-db-tools.py

## pre-reqs
`python3.6`
the team is converging on `psycopg2` as the standard python library for accessing Postgres.  To install:

`$ pip install psycopg2-binary`

or for Fedora:
```
sudo dnf install python-devel postgresql-devel
pip install psycopg2
```

## setting up a local instance of the DB

spin up an instance of postgress in docker:
`docker run -d --name my_postgres -v my_dbdata:/var/lib/postgresql/data -p 54320:5432 postgres:14`

install psql tool: (not required but helpful for setting up the DB & having another path into the DB - remotely too)
`sudo dnf install psql`

connect it to your local instance:
`psql -h localhost -p 54320 -U postgres`

create the database
`createdb gd_corpus_test -h localhost -p 54320 -U postgres`



## make sure the tool connects
`source` a config to pick up Postgres config:
`source <config.sh>`

where `config.sh`:

**FOR LOCAL DB ACCESS:**
```
# for access to GD_DB on local
export GD_DB_CONF=env/gd_db.conf

# Inside of the configuration file
cat <<EOF > env/gd_db.conf
database = gd_corpus_tester
hostname = localhost     # for example  "aws-us-east-1-portal.4.dblayer.com"
port = 54320
username = postgres
password = ""
EOF
```

_note:_ make another copy of this file and populate it with the host secrets & you can interact with the host DB using `gd_db_tools.py`
(details from cloud.ibm.com postgres service):

**FOR HOST ACCESS:**
```
export GD_DB_CONF=env/gd_db.conf

# for access to GD_DB on host
cat <<EOF > env/gd_db.conf
database = ibmclouddb
hostname = 9f5cefd3-2130-430b-8e28-bee3a0f8e105.3c7f6c12a66c4324800651be37a77ceb.databases.appdomain.cloud     # for example  "aws-us-east-1-portal.4.dblayer.com"
port = 32566
username = "[redacted]"
password = "[redacted]"
EOF
```

Without parameters `gd_db_tools.py` will confirm DB access:
```
> python gd_db_tools.py
Connecting to database
	-> gd_corpus_tester on localhost:54320
Connected!

Only connection test.
Usage:
             python gd_db_tools.py [-ct] | [-cu <user_id>:read_only|read_write|admin]| [-du <user_id>] | [-t] | [-ls]
                 -ct,    --create-tables        create all tables
                 -cu,    --create-user          create PSQL user & assign random access key
                 -du,    --drop-user            drop PSQL user & associated KP key
                 -t,     --test-token-add       add test token
                 -ls,    --list-rows            lists all rows in all tables
                         --tear-down-tables     destroys all tables - after confirmation

Success exiting
```
Other command-line options allow you to manipulate the database you've connected to - whether that's local or remote.

## Key Protect access:
```
# for access to KP
export GD_KP_REGION="us-east"
export GD_KP_RESOURCE_GROUP="whitewater-detect-secrets"
export GD_KP_ACCOUNT_ID="26bb005a5183cf92d5694dd5e93c03c2"

export GD_KP_SERVICE_INSTANCE="a0bdc0fb-9638-407b-b4ca-832cf0ad865e" # from `ibmcloud resource service-instance 'Key Protect - gd - prod' --id`
```

And:
```
export GD_KP_KEY=(ibmcloud iam oauth-tokens | string split " ")[-1]
```
to use your ibmcloud ID's OAUTH token (in `fish` & temp - it will expire!) to read / write from KP.  this will save you from copying a permenant key for KP to your local.
