#all: cpexec
all: buildlib

buildlib:
	python3 compile.py build_ext --inplace

package:
	mkdir -p dist/pyptsiem4
	cp pyptsiem4/*.so dist/pyptsiem4
	cp mpszabbix.py dist/
	cp LICENSE dist/
	cp README.md dist/

# создаем архив без полного пути, только файлы. потом будет удобнее разливать
	tar caf mpszabbix.tar.xz -C dist/ .

install: buildlib
	cp mpszabbix.py /usr/lib/zabbix/externalscripts
	mkdir -p /usr/lib/zabbix/externalscripts/pyptsiem4
	cp pyptsiem4/*.so /usr/lib/zabbix/externalscripts/pyptsiem4

clean:
	rm -rf build/*
	rm -rf dist/*
