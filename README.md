# ucp-migrate-users:1.1
Generate a list of current accounts from the local Docker Universal Control Plane (UCP) and copy them over to a new UCP.

## Usage
### Interactive Mode
~~~
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock squizzi/ucp-migrate-users -i
~~~

### Non-Interactive Mode
**Note:** Non-interactive mode lacks much of the same variable validation that interactive mode has, ensure the information provided in the flags is correct, see the below example for details.

~~~
docker run --rm -it \
-v /var/run/docker.sock:/var/run/docker.sock squizzi/ucp-migrate-users \
--ucp-to https://ucp2.example.com \
--ucp-to-user admin \
--ucp-to-password foobar \
-P changeme123
~~~
