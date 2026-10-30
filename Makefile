GO      ?= $(shell command -v go 2>/dev/null || echo /usr/local/go/bin/go)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: all clean test vet build release release-archive build-spec build-spec-cross build-spec-depguard gui-doctor gui-buildspec gui-buildspec-windows dist-buildspec dist-buildspec-windows

all: build

build:
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o permissionreset ./cmd/permissionreset/
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o generate-tree ./cmd/generate_tree/
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o sweep ./cmd/sweep/
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o build-spec ./cmd/build_spec/

test:
	$(GO) test ./...

# Regenerates the vendored XDR bindings into one file.
#
# Pinned to the TAG v0.1.3, not a commit. Commit cef4592 cannot be `go run` at
# all -- the published module omits its goyacc-generated parser (cmd/goxdr/parse.go
# and header.go) and fails with "undefined: T_CONST". Building it locally means
# running goyacc, a second unpinned input, which defeats the point of pinning.
# The tagged release ships the generated parser and works from a clean machine.
#
# ONE invocation with BOTH .x files. goxdr's -B "implies -b", so two invocations
# emit the runtime boilerplate into both outputs and every runtime symbol is
# declared twice in one Go package.
#
# -lax-discriminants is required by callback_sec_parms4, whose discriminant is a
# uint32_t while its cases are auth_flavor members. The relaxation stays in this
# command rather than editing RFC text in the vendored .x.
#
# This target also proves the generated file was never hand-edited: running it
# must leave the working tree clean.
regen-xdr:
	go run github.com/xdrpp/goxdr/cmd/goxdr@v0.1.3 \
	  -B -enum-comments -fmt -lax-discriminants \
	  -p xdr internal/nfs41/xdr/nfs4.x internal/nfs41/xdr/rpc.x \
	  > internal/nfs41/xdr/xdr_generated.go

vet:
	$(GO) vet ./...

clean:
	rm -f permissionreset generate-tree sweep build-spec
	rm -rf dist/

# Platforms shipped as release archives. macOS needs BOTH architectures: Go
# emits single-architecture binaries and the universal Mach-O that would
# collapse them needs Apple's lipo, which the Linux runners do not have.
#
# The Windows follow-up appends windows/amd64 here and a .zip rule below; the
# archive naming already leaves room for it.
RELEASE_PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# Files shipped alongside the binaries in every archive.
RELEASE_DOCS = README.md LICENSE INSTALL.md
# Set-SaclOnly (Windows, SMB side) ships in every archive with a build-spec.exe for -Spec.
SACLONLY_FILES = $(addprefix tools/set-saclonly/,Set-SaclOnly.ps1 SaclPlan.ps1 SaclOnly.cs README.md)

# Each archive unpacks into ONE top-level directory named after itself, so
# extraction never scatters files into the operator's working directory.
# .tar.gz rather than zip on macOS because it preserves the executable bit.
release: clean
	@mkdir -p dist
	@for platform in $(RELEASE_PLATFORMS); do \
	  goos=$${platform%/*}; goarch=$${platform#*/}; \
	  name=permissionreset_$(VERSION)_$${goos}_$${goarch}; \
	  stage=dist/$${name}; \
	  mkdir -p $${stage}; \
	  echo "building $${name}"; \
	  GOOS=$${goos} GOARCH=$${goarch} CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $${stage}/permissionreset ./cmd/permissionreset/ || exit 1; \
	  GOOS=$${goos} GOARCH=$${goarch} CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $${stage}/generate-tree ./cmd/generate_tree/ || exit 1; \
	  GOOS=$${goos} GOARCH=$${goarch} CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $${stage}/sweep ./cmd/sweep/ || exit 1; \
	  GOOS=$${goos} GOARCH=$${goarch} CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $${stage}/build-spec ./cmd/build_spec/ || exit 1; \
	  cp $(RELEASE_DOCS) $${stage}/ || exit 1; \
	  mkdir -p $${stage}/tools/set-saclonly && \
	  cp $(SACLONLY_FILES) $${stage}/tools/set-saclonly/ || exit 1; \
	  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $${stage}/tools/set-saclonly/build-spec.exe ./cmd/build_spec/ || exit 1; \
	done
	@echo ""
	@echo "Built $(VERSION) ($(COMMIT)):"
	@ls -lh dist/*/

# release-archive packs the staging directories built by `release` and then
# removes them, so `for file in dist/*` in the release workflow sees archives
# and nothing else. It is a separate target because the SBOM step needs the
# unpacked binaries: `go version -m` reads a file on disk and cannot look inside
# a tarball.
release-archive:
	@cd dist && for d in */; do \
	  name=$${d%/}; \
	  echo "packing $${name}.tar.gz"; \
	  tar -czf $${name}.tar.gz $${name} || exit 1; \
	  rm -rf $${name}; \
	done
	@ls -lh dist/

# build-spec: host build (native GOOS/GOARCH).
build-spec:
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o build-spec ./cmd/build_spec/

# build-spec-cross: produce per-platform binaries and a Windows ZIP under dist/.
# The ZIP contains the .exe plus README.md, LICENSE, and INSTALL.md.
# Skips the zip step and prints a warning if the `zip` command is not available.
build-spec-cross:
	@mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o dist/build-spec-linux-amd64   ./cmd/build_spec/
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o dist/build-spec-darwin-amd64  ./cmd/build_spec/
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o dist/build-spec-darwin-arm64  ./cmd/build_spec/
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o dist/build-spec.exe ./cmd/build_spec/
	@if command -v zip >/dev/null 2>&1; then \
	  mkdir -p dist/build-spec-windows-amd64; \
	  cp dist/build-spec.exe dist/build-spec-windows-amd64/; \
	  cp README.md LICENSE INSTALL.md dist/build-spec-windows-amd64/; \
	  cd dist && zip -r build-spec-windows-amd64.zip build-spec-windows-amd64/; \
	  rm -rf dist/build-spec-windows-amd64 dist/build-spec.exe; \
	  echo "Produced dist/build-spec-windows-amd64.zip"; \
	else \
	  echo "WARNING: zip not found — skipping dist/build-spec-windows-amd64.zip"; \
	fi
	@ls -lh dist/build-spec-*

# build-spec-depguard: assert the Windows build does not pull in walk, apply, or treegen.
build-spec-depguard:
	@echo "Checking build-spec Windows dependencies..."
	@deps=$$(GOOS=windows GOARCH=amd64 $(GO) list -deps ./cmd/build_spec/ 2>&1); \
	bad=""; \
	for pkg in internal/walk internal/apply internal/treegen; do \
	  if echo "$$deps" | grep -q "$$pkg"; then \
	    bad="$$bad $$pkg"; \
	  fi; \
	done; \
	if [ -n "$$bad" ]; then \
	  echo "FAIL: cmd/build_spec Windows build imports forbidden packages:$$bad"; \
	  exit 1; \
	fi; \
	echo "OK: no forbidden dependencies"

# build-spec desktop GUI targets. These require the Wails CLI and are outside the root `build`
# target to keep the root cgo-free.
gui-doctor:
	cd gui/buildspec && PATH="/usr/local/go/bin:$$HOME/go/bin:$$PATH" wails doctor

gui-buildspec:
	cd gui/buildspec && PATH="/usr/local/go/bin:$$HOME/go/bin:$$PATH" wails build -ldflags "-X main.version=$(VERSION)"

gui-buildspec-windows:
	cd gui/buildspec && PATH="/usr/local/go/bin:$$HOME/go/bin:$$PATH" wails build -platform windows/amd64 -webview2 embed -ldflags "-X main.version=$(VERSION)"

# dist-buildspec: zip the built buildspec.app under dist/, name and checksum by
# main.version. Depends on gui-buildspec so the .app is never stale relative to
# the archive.
dist-buildspec: gui-buildspec
	@mkdir -p dist
	@name=buildspec_$(VERSION)_darwin; \
	rm -rf dist/$$name dist/$$name.zip; \
	mkdir -p dist/$$name; \
	cp -R gui/buildspec/build/bin/buildspec.app dist/$$name/; \
	cd dist && zip -qr $$name.zip $$name && rm -rf $$name && shasum -a 256 $$name.zip > $$name.zip.sha256
	@ls -lh dist/buildspec_$(VERSION)_darwin.zip*

# dist-buildspec-windows: zip the built buildspec.exe under dist/, name and
# checksum by main.version. Depends on gui-buildspec-windows.
dist-buildspec-windows: gui-buildspec-windows
	@mkdir -p dist
	@name=buildspec_$(VERSION)_windows_amd64; \
	rm -rf dist/$$name dist/$$name.zip; \
	mkdir -p dist/$$name; \
	cp gui/buildspec/build/bin/buildspec.exe dist/$$name/; \
	cd dist && zip -qr $$name.zip $$name && rm -rf $$name && shasum -a 256 $$name.zip > $$name.zip.sha256
	@ls -lh dist/buildspec_$(VERSION)_windows_amd64.zip*
