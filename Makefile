all: webserver

%: %.xpl
	xmlplcc $<

example: webserver example.xml
	./webserver example <example.xml

install:
	ssh root@coffland.com /var/www/install.sh

commit: webserver webserver.xml
	rm -rf output
	./webserver output <webserver.xml
	rsync -rltD output/ root@coffland.com:/var/www/

test: webserver
	./webserver test <webserver.xml

clean:
	rm -rf test output webserver *~

.PHONY: example install commit test
