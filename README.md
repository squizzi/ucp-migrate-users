# ucp-migrate-users:1.0
Generate a list of current accounts from a given Docker UCP and copy them
over to a new UCP.

## Usage
### Interactive Mode
~~~
docker run --rm -it squizzi/ucp-migrate-users -i
~~~

### Non-Interactive Mode
**Note**: At this time, non-interactive mode lacks much of the same variable
validation that interactive mode has, ensure the information provided in the
flags is correct, see the below example for details.

Validation will be fixed in a later release.
~~~
docker run --rm -it squizzi/ucp-migrate-users \
--ucp-from https://ucp1.example.com \
--ucp-to https://ucp2.example.com \
--ucp-from-user admin \
--ucp-from-password foobar \
--ucp-to-user admin \
--ucp-to-password barfoo \
-P changeme123
~~~
