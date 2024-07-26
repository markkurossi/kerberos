help:
	@echo "Targets: build shell"

HOSTS = --add-host=krb.markkurossi.com:127.0.0.1 \
	--add-host=mac.markkurossi.com:host-gateway

build:
	docker image build -t builder:1.0 .

shell:
	docker run -v $(CURDIR):/work $(HOSTS) -it builder:1.0 bash
