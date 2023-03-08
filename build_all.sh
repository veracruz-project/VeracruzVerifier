#docker-compose down
#docker rmi veracruzverifier-provisioning veracruzverifier-vts veracruzverifier-verifier
rm -f ./vts/vts
go build -o ./vts/vts -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/vts/cmd/vts-service
rm -f ./provisioning/provisioning
go build -o ./provisioning/provisioning -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/provisioning/cmd/provisioning-service
rm -f proxy_attestation_server
go build .
#docker-compose up
