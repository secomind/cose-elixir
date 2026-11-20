defmodule COSETest.Encrypt0 do
  use ExUnit.Case, async: true

  alias COSE.Keys.Symmetric
  alias COSE.Messages.Encrypt0

  @cipher_suite :aes_128_gcm

  setup_all do
    key = %Symmetric{k: :crypto.strong_rand_bytes(16), alg: @cipher_suite}
    iv = :crypto.strong_rand_bytes(12)

    %CBOR.Tag{tag: 16, value: [phdr, uhdr, ciphertext]} =
      "content to encrypt"
      |> Encrypt0.build(%{alg: @cipher_suite}, %{iv: COSE.tag_as_byte(iv)})
      |> Encrypt0.encrypt(@cipher_suite, key, iv)
      |> Encrypt0.encode()

    %{key: key, iv: iv, phdr: phdr, uhdr: uhdr, ciphertext: ciphertext}
  end

  describe "decrypt_decode/3" do
    test "decrypts a valid message", context do
      encoded = encode_message(context.phdr, context.uhdr, context.ciphertext)

      assert {:ok, %Encrypt0{payload: "content to encrypt"}} =
               Encrypt0.decrypt_decode(encoded, @cipher_suite, context.key)
    end

    test "rejects a message that doesn't decrypt with the given key", context do
      other_key = %Symmetric{k: :crypto.strong_rand_bytes(16), alg: @cipher_suite}
      encoded = encode_message(context.phdr, context.uhdr, context.ciphertext)

      assert {:error, :decryption_failed} ==
               Encrypt0.decrypt_decode(encoded, @cipher_suite, other_key)
    end

    test "rejects a protected header that is not a byte string", context do
      for phdr <- malformed_phdrs() do
        assert_malformed(context, encode_message(phdr, context.uhdr, context.ciphertext))
      end
    end

    test "rejects protected header bytes that don't decode to a single map", context do
      for phdr <- malformed_phdr_bytes() do
        assert_malformed(context, encode_message(phdr, context.uhdr, context.ciphertext))
      end
    end

    test "rejects an unprotected header that is not a map", context do
      for uhdr <- malformed_uhdrs() do
        assert_malformed(context, encode_message(context.phdr, uhdr, context.ciphertext))
      end
    end

    test "rejects a message without an IV", context do
      for uhdr <- [%{} | malformed_iv_uhdrs()] do
        assert_malformed(context, encode_message(context.phdr, uhdr, context.ciphertext))
      end
    end

    test "rejects an IV of the wrong length", context do
      for iv_size <- [0, 8, 13, 16] do
        uhdr = %{5 => COSE.tag_as_byte(:crypto.strong_rand_bytes(iv_size))}
        assert_malformed(context, encode_message(context.phdr, uhdr, context.ciphertext))
      end
    end

    test "rejects a ciphertext shorter than the authentication tag", context do
      for ciphertext <- short_ciphertexts() do
        assert_malformed(context, encode_message(context.phdr, context.uhdr, ciphertext))
      end
    end

    test "rejects a ciphertext that is not a byte string", context do
      for ciphertext <- malformed_ciphertexts() do
        assert_malformed(context, encode_message(context.phdr, context.uhdr, ciphertext))
      end
    end

    test "rejects a value that is not an Encrypt0 message", context do
      for msg <- non_encrypt0_messages(context) do
        assert_malformed(context, CBOR.encode(msg))
      end
    end

    test "returns the CBOR error for a binary that is not CBOR", context do
      assert {:error, _reason} = Encrypt0.decrypt_decode(<<0x1C>>, @cipher_suite, context.key)
    end

    test "rejects a key of the wrong size", context do
      encoded = encode_message(context.phdr, context.uhdr, context.ciphertext)

      for size <- [0, 3, 15, 32] do
        key = %Symmetric{k: :crypto.strong_rand_bytes(size), alg: @cipher_suite}
        assert {:error, :invalid_key} == Encrypt0.decrypt_decode(encoded, @cipher_suite, key)
      end
    end

    test "derives the key size from the cipher suite" do
      key = %Symmetric{k: :crypto.strong_rand_bytes(32), alg: :aes_256_gcm}
      iv = :crypto.strong_rand_bytes(12)

      encoded =
        "content to encrypt"
        |> Encrypt0.build(%{alg: :aes_256_gcm}, %{iv: COSE.tag_as_byte(iv)})
        |> Encrypt0.encrypt_encode(:aes_256_gcm, key, iv)

      assert {:ok, %Encrypt0{payload: "content to encrypt"}} =
               Encrypt0.decrypt_decode(encoded, :aes_256_gcm, key)
    end

    test "never raises on random Encrypt0-shaped messages", context do
      for _ <- 1..2_000 do
        fields = [random_phdr(context.phdr), random_uhdr(), random_ciphertext()]
        msg = %CBOR.Tag{tag: 16, value: Enum.take(fields, Enum.random([2, 3, 3, 3]))}

        assert_rejected(Encrypt0.decrypt_decode(CBOR.encode(msg), @cipher_suite, context.key))
      end
    end

    test "never raises on random CBOR values", context do
      for _ <- 1..2_000 do
        encoded = CBOR.encode(random_term(3))
        assert_rejected(Encrypt0.decrypt_decode(encoded, @cipher_suite, context.key))
      end
    end
  end

  describe "decode/1" do
    test "decodes a valid message", context do
      assert {:ok, %Encrypt0{phdr: %{alg: @cipher_suite}, uhdr: %{iv: iv}}} =
               Encrypt0.decode(message(context.phdr, context.uhdr, context.ciphertext))

      assert iv == COSE.tag_as_byte(context.iv)
    end

    test "rejects a protected header that is not a byte string", context do
      for phdr <- malformed_phdrs() do
        assert_decode_malformed(message(phdr, context.uhdr, context.ciphertext))
      end
    end

    test "rejects protected header bytes that don't decode to a single map", context do
      for phdr <- malformed_phdr_bytes() do
        assert_decode_malformed(message(phdr, context.uhdr, context.ciphertext))
      end
    end

    test "rejects an unprotected header that is not a map", context do
      for uhdr <- malformed_uhdrs() do
        assert_decode_malformed(message(context.phdr, uhdr, context.ciphertext))
      end
    end

    test "rejects headers that are structs", context do
      assert_decode_malformed(message(context.phdr, ~U[2020-01-01 00:00:00Z], context.ciphertext))
    end

    test "rejects a message without an IV", context do
      assert_decode_malformed(message(context.phdr, %{}, context.ciphertext))
    end

    test "rejects an IV that is not a byte string", context do
      for uhdr <- malformed_iv_uhdrs() do
        assert_decode_malformed(message(context.phdr, uhdr, context.ciphertext))
      end
    end

    test "rejects a ciphertext shorter than the authentication tag", context do
      for ciphertext <- short_ciphertexts() do
        assert_decode_malformed(message(context.phdr, context.uhdr, ciphertext))
      end
    end

    test "rejects a ciphertext that is not a byte string", context do
      for ciphertext <- malformed_ciphertexts() do
        assert_decode_malformed(message(context.phdr, context.uhdr, ciphertext))
      end
    end

    test "rejects a value that is not an Encrypt0 message", context do
      for msg <- non_encrypt0_messages(context) do
        assert_decode_malformed(msg)
      end
    end
  end

  describe "decrypt/5" do
    test "rejects an IV of the wrong length", context do
      {:ok, msg} = Encrypt0.decode(message(context.phdr, context.uhdr, context.ciphertext))

      for iv <- [<<>>, :crypto.strong_rand_bytes(8), nil] do
        assert {:error, :malformed_message} ==
                 Encrypt0.decrypt(msg, @cipher_suite, context.key, iv)
      end
    end
  end

  defp message(phdr, uhdr, ciphertext) do
    %CBOR.Tag{tag: 16, value: [phdr, uhdr, ciphertext]}
  end

  defp encode_message(phdr, uhdr, ciphertext) do
    CBOR.encode(message(phdr, uhdr, ciphertext))
  end

  defp malformed_phdrs, do: [%{1 => 1}, 5, "text"]

  defp malformed_phdr_bytes do
    Enum.map(
      [
        <<>>,
        CBOR.encode([1]),
        CBOR.encode(%{1 => 1}) <> <<0>>,
        CBOR.encode(%CBOR.Tag{tag: 1, value: 3}),
        <<0x1C>>
      ],
      &COSE.tag_as_byte/1
    )
  end

  defp malformed_uhdrs, do: [7, [1, 2], %CBOR.Tag{tag: 1, value: 3}, COSE.tag_as_byte(<<1>>)]

  defp malformed_iv_uhdrs, do: [%{5 => 3}, %{5 => "text"}, %{5 => nil}]

  defp short_ciphertexts do
    Enum.map([0, 3, 15], &COSE.tag_as_byte(:crypto.strong_rand_bytes(&1)))
  end

  defp malformed_ciphertexts, do: [nil, 5, "text", %{}]

  defp non_encrypt0_messages(context) do
    [
      %CBOR.Tag{tag: 17, value: [context.phdr, context.uhdr, context.ciphertext]},
      %CBOR.Tag{tag: 16, value: [context.phdr, context.uhdr]},
      %CBOR.Tag{tag: 16, value: [context.phdr, context.uhdr, context.ciphertext, 1]},
      [context.phdr, context.uhdr, context.ciphertext],
      5
    ]
  end

  defp assert_decode_malformed(msg) do
    assert {:error, :malformed_message} == Encrypt0.decode(msg)
  end

  defp assert_malformed(context, encoded) do
    assert {:error, :malformed_message} ==
             Encrypt0.decrypt_decode(encoded, @cipher_suite, context.key)
  end

  defp assert_rejected(result) do
    assert {:error, _reason} = result
  end

  defp random_phdr(valid_phdr) do
    Enum.random([
      valid_phdr,
      COSE.tag_as_byte(CBOR.encode(random_term(2))),
      Enum.random(-1_000..1_000),
      [random_term(1)],
      %{1 => random_term(1)},
      nil
    ])
  end

  defp random_uhdr do
    Enum.random([
      %{5 => COSE.tag_as_byte(:rand.bytes(Enum.random([0, 8, 12, 12, 16])))},
      %{},
      random_term(2)
    ])
  end

  defp random_ciphertext do
    Enum.random([COSE.tag_as_byte(:rand.bytes(Enum.random(0..40))), random_term(2)])
  end

  defp random_term(0), do: random_scalar()

  defp random_term(depth) do
    case Enum.random(1..4) do
      1 -> Enum.map(1..Enum.random(0..3), fn _ -> random_term(depth - 1) end)
      2 -> Map.new(1..Enum.random(0..3), fn _ -> {random_scalar(), random_term(depth - 1)} end)
      3 -> %CBOR.Tag{tag: Enum.random([16, 99]), value: random_term(depth - 1)}
      4 -> random_scalar()
    end
  end

  defp random_scalar do
    case Enum.random(1..6) do
      1 -> Enum.random(-1_000..1_000)
      2 -> :rand.bytes(Enum.random(0..20)) |> Base.encode64()
      3 -> COSE.tag_as_byte(CBOR.encode(random_term(1)))
      4 -> nil
      5 -> true
      6 -> false
    end
  end
end
