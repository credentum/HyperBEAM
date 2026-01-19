--- @module test_crypto
--- Contains test functions for the Lua crypto library.

--- @function crypto_hash_sha256_test
--- Tests that SHA256 hashing works and returns 32 bytes.
function crypto_hash_sha256_test()
    local hash = crypto.hash("sha256", "hello")
    if hash and #hash == 32 then
        return "ok"
    else
        return "error", "SHA256 should return 32 bytes"
    end
end

--- @function crypto_hash_known_vector_test
--- Tests SHA256 against a known test vector.
function crypto_hash_known_vector_test()
    local hash = crypto.hash("sha256", "test")
    local hex = crypto.to_hex(hash)
    local expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    if hex == expected then
        return "ok"
    else
        return "error", "SHA256 mismatch: got " .. (hex or "nil")
    end
end

--- @function crypto_hash_invalid_algo_test
--- Tests that unknown algorithms return an error.
function crypto_hash_invalid_algo_test()
    local result = crypto.hash("not_an_algo", "data")
    if result == "error" then
        return "ok"
    else
        return "error", "Should reject unknown algorithm"
    end
end

--- @function crypto_verify_exists_test
--- Tests that crypto.verify function exists.
function crypto_verify_exists_test()
    if type(crypto.verify) == "function" then
        return "ok"
    else
        return "error", "crypto.verify not available"
    end
end

--- @function crypto_hex_roundtrip_test
--- Tests that to_hex and from_hex are inverses.
function crypto_hex_roundtrip_test()
    local original = "Hello, World!"
    local hex = crypto.to_hex(original)
    local decoded = crypto.from_hex(hex)
    if decoded == original then
        return "ok"
    else
        return "error", "Hex roundtrip failed"
    end
end

--- @function crypto_to_hex_test
--- Tests to_hex produces correct output.
function crypto_to_hex_test()
    local hex = crypto.to_hex("Hello")
    if hex == "48656c6c6f" then
        return "ok"
    else
        return "error", "to_hex mismatch: got " .. (hex or "nil")
    end
end

--- @function crypto_from_hex_test
--- Tests from_hex produces correct output.
function crypto_from_hex_test()
    local bin = crypto.from_hex("48656c6c6f")
    if bin == "Hello" then
        return "ok"
    else
        return "error", "from_hex mismatch: got " .. (bin or "nil")
    end
end

--- @function crypto_from_hex_invalid_test
--- Tests that invalid hex strings return an error.
function crypto_from_hex_invalid_test()
    local result = crypto.from_hex("not_hex_ZZZ")
    if result == "error" then
        return "ok"
    else
        return "error", "Should reject invalid hex"
    end
end

--- @function crypto_random_bytes_disabled_test
--- Tests that random_bytes is disabled by default (AO Panel requirement).
function crypto_random_bytes_disabled_test()
    local result = crypto.random_bytes(32)
    if result == "error" then
        return "ok"
    else
        return "error", "random_bytes should be disabled by default"
    end
end

--- @function crypto_survivor_trace_test
--- Tests the Forge use case for computing survivor_trace.
function crypto_survivor_trace_test()
    local input = '{"scar_id":"test","myth_id":"guardian","ts":123}'
    local hash = crypto.hash("sha256", input)
    local trace = crypto.to_hex(hash)
    if trace and #trace == 64 then  -- 32 bytes = 64 hex chars
        return "ok"
    else
        return "error", "survivor_trace should be 64 hex chars"
    end
end

--- @function crypto_hash_sha512_test
--- Tests SHA512 hashing works and returns 64 bytes.
function crypto_hash_sha512_test()
    local hash = crypto.hash("sha512", "hello")
    if hash and #hash == 64 then
        return "ok"
    else
        return "error", "SHA512 should return 64 bytes"
    end
end

--- @function crypto_hash_empty_input_test
--- Tests hashing an empty string works correctly.
function crypto_hash_empty_input_test()
    local hash = crypto.hash("sha256", "")
    local hex = crypto.to_hex(hash)
    -- SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    local expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if hex == expected then
        return "ok"
    else
        return "error", "Empty string hash mismatch"
    end
end

--- @function crypto_functions_exist_test
--- Tests that all expected crypto functions exist.
function crypto_functions_exist_test()
    local functions = {"hash", "verify", "to_hex", "from_hex", "random_bytes"}
    for _, fname in ipairs(functions) do
        if type(crypto[fname]) ~= "function" then
            return "error", "Missing function: crypto." .. fname
        end
    end
    return "ok"
end
