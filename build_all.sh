docker compose down
docker rmi veracruzverifier_provisioning veracruzverifier_vts veracruzverifier_verifier
go build -o ./vts github.com/veraison/services/vts/cmd
go build -o ./provisioning github.com/veraison/services/provisioning/cmd
go build -o ./corim-psa-decoder github.com/veraison/services/provisioning/plugins/corim-psa-decoder
go build -o ./corim-nitro-decoder github.com/veraison/services/provisioning/plugins/corim-nitro-decoder
go build -o ./scheme-psa-iot github.com/veraison/services/vts/plugins/scheme-psa-iot
go build -o ./scheme-aws-nitro github.com/veraison/services/vts/plugins/scheme-aws-nitro
go build .
docker compose up
