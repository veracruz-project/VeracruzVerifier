docker-compose down
docker rmi veracruzverifier-provisioning veracruzverifier-vts veracruzverifier-verifier
rm -f ./vts
go build -o ./vts github.com/veraison/services/vts/cmd
rm -f ./provisioning
go build -o ./provisioning github.com/veraison/services/provisioning/cmd
rm -f ./corim-psa-decoder
go build -o ./corim-psa-decoder github.com/veraison/services/provisioning/plugins/corim-psa-decoder
rm -f ./corim-nitro-decoder
go build -o ./corim-nitro-decoder github.com/veraison/services/provisioning/plugins/corim-nitro-decoder
rm -f ./scheme-psa-iot
go build -o ./scheme-psa-iot github.com/veraison/services/vts/plugins/scheme-psa-iot
rm -f ./scheme-aws-nitro
go build -o ./scheme-aws-nitro github.com/veraison/services/vts/plugins/scheme-aws-nitro
rm -f VeracruzVerifier
go build .
docker-compose up
