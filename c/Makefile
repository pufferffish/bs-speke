bs_speke.js:
	emcc -Oz -s WASM=0 \
		-s EXPORTED_FUNCTIONS='["_free", "_malloc", "_bs_speke_size", "_bs_speke_init", "_bs_speke_get_salt", "_bs_speke_derive_secret", "_bs_speke_register", "_bs_speke_login_key_exchange"]' \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s MODULARIZE=1 \
		-s 'EXPORT_NAME="bs_speke"' \
		-s SINGLE_FILE=1 \
		-s AGGRESSIVE_VARIABLE_ELIMINATION=1 \
		-s ALIASING_FUNCTION_POINTERS=1 \
		-o ../js/bs_speke.js \
		-Wno-pointer-sign \
		--cache "/tmp/emcc-cache/" \
		bs_speke.c monocypher.c