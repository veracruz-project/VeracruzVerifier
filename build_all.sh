#docker-compose down
#docker rmi veracruzverifier-provisioning veracruzverifier-vts veracruzverifier-verifier
rm -f ./vts/vts
echo building vts
go build -o ./vts/vts -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/vts/cmd/vts-service
echo building provisioing
rm -f ./provisioning/provisioning
go build -o ./provisioning/provisioning -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/provisioning/cmd/provisioning-service
echo building proxy_attestation_Server
rm -f proxy_attestation_server
go build .
#docker-compose up
