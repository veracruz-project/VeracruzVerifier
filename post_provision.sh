#curl -X POST -H 'Content-Type: application/corim-unsigned+cbor; profile=http://arm.com/psa/iot/1' --data-binary "@cbor_bin" localhost:8888/endorsement-provisioning/v1/submit
/home/dermil01/go/bin/cocli comid create --template MyComidPsaIak.json
/home/dermil01/go/bin/cocli comid create --template AWSNitroComid.json
/home/dermil01/go/bin/cocli corim create -m MyComidPsaIak.cbor -t corimMini.json -o psa_corim.cbor
curl -X POST -H 'Content-Type: application/corim-unsigned+cbor; profile=http://arm.com/psa/iot/1' --data-binary "@psa_corim.cbor" localhost:8888/endorsement-provisioning/v1/submit
/home/dermil01/go/bin/cocli corim create -m AWSNitroComid.cbor -t corimMini.json -o nitro_corim.cbor
curl -X POST -H 'Content-Type: application/corim-unsigned+cbor; profile=http://aws.com/nitro' --data-binary "@nitro_corim.cbor" localhost:8888/endorsement-provisioning/v1/submit
