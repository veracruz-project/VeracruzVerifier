location=$(curl  -d 'nonce=12345' -i -L localhost:8080/challenge-response/v1/newSession/ | tr -d '\r' | awk '/Location: session\/*/{ print $2}') 
echo $location
echo Between two ferns

url="localhost:8080/challenge-response/v1/${location}"
echo $url
curl -X POST -H 'Content-Type: application/psa-attestation-token' --data-binary "@psa-token.cbor" ${url}