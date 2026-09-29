.PHONY: build test package test-package clean

build:
	./scripts/build.sh

test: build
	/usr/bin/ruby Tests/relay_integration_test.rb
	/usr/bin/ruby Tests/race_integration_test.rb
	/bin/sh Tests/config_test.sh
	/bin/sh Tests/system_scripts_test.sh
	/bin/sh Tests/tlr_test.sh
	/bin/sh Tests/network_installer_test.sh
	/bin/sh Tests/project_files_test.sh

package: build
	./scripts/package.sh "$(VERSION)"

test-package:
	/bin/sh Tests/package_test.sh

clean:
	rm -rf .build dist
