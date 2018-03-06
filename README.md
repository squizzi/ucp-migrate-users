# ucp-migrate-users
Generate a list of current accounts from a given Docker UCP and copy them
over to a new UCP.

## Usage
### Interactive Mode
~~~
docker run --rm -it squizzi/ucp-migrate-users -i
~~~

### Non-Interactive Mode
~~~
docker run --rm -it squizzi/ucp-migrate-users \
--ucp-from ucp1.example.com \
--ucp-to ucp2.example.com \
--ucp-from-user admin \
--ucp-from-password foobar \
--ucp-to-user admin \
--ucp-to-password barfoo \
-P changeme123
~~~
