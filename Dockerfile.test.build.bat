rmdir "bin/publish" /s /q
docker build -f Dockerfile.test.build -t com-moonlay-service-auth-webapi:test-build .
docker rm com-moonlay-service-auth-webapi-test-build-container
docker create --name com-moonlay-service-auth-webapi-test-build-container com-moonlay-service-auth-webapi:test-build
docker cp com-moonlay-service-auth-webapi-test-build-container:/out ./bin/publish
docker build -f ./Dockerfile.test -t com-moonlay-service-auth-webapi:test .