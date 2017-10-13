rmdir "bin" /s /q
docker build --no-cache -f Dockerfile.test.build -t com-moonlay-service-auth-webapi:test-build .
docker rm com-moonlay-service-auth-webapi-test-build-container
docker create --name com-moonlay-service-auth-webapi-test-build-container com-moonlay-service-auth-webapi:test-build
md bin
docker cp com-moonlay-service-auth-webapi-test-build-container:/out ./bin/publish
docker build --no-cache -f Dockerfile.test -t com-moonlay-service-auth-webapi:test .
docker rm com-moonlay-service-auth-webapi-test-build-container