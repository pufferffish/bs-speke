bs_speke.js:
	emcc -O3 -s WASM=1 \
		-s EXPORTED_FUNCTIONS='["_free", "_malloc", "_bs_speke_size", "_bs_speke_init", "_bs_speke_get_salt", "_bs_speke_derive_secret", "_bs_speke_register", "_bs_speke_login_key_exchange"]' \
		-s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s MODULARIZE=1 \
		-s EXPORT_ES6=1 \
		-s NO_FILESYSTEM=1 \
		-s DEMANGLE_SUPPORT=0 \
        -s ASSERTIONS=0 \
        -s TOTAL_MEMORY=16MB \
        -s BINARYEN_MEM_MAX=2147418112 \
		-s 'EXPORT_NAME="bs_speke"' \
		-s SINGLE_FILE=1 \
		-s AGGRESSIVE_VARIABLE_ELIMINATION=1 \
		-s ALIASING_FUNCTION_POINTERS=1 \
		-o ../js/bs_speke.js \
		-Wno-pointer-sign \
		--cache "/tmp/emcc-cache/" \
		bs_speke.c monocypher.c