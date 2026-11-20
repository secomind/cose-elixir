defmodule COSETest do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Headers}

  test "generate okp keys" do
    assert Keys.OKP.generate(:enc).kty == :okp
    assert Keys.OKP.generate(:enc).crv == :x25519
    assert Keys.OKP.generate(:sig).crv == :ed25519
  end

  test "encode ecc key to map" do
    key = Keys.ECC.generate(:es256)
    map = Keys.encode(key)

    assert map[-2] == %CBOR.Tag{tag: :bytes, value: key.x}
    assert map[-3] == %CBOR.Tag{tag: :bytes, value: key.y}
    refute Map.has_key?(map, -4)
  end

  test "encode ecc key to cbor" do
    key = Keys.ECC.generate(:es256)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-2] == %CBOR.Tag{tag: :bytes, value: key.x}
    assert map[-3] == %CBOR.Tag{tag: :bytes, value: key.y}
  end

  test "encode okp key to map" do
    key = Keys.OKP.generate(:sig)
    map = Keys.encode(key)

    assert map[-2] == %CBOR.Tag{tag: :bytes, value: key.x}
    refute Map.has_key?(map, -4)
  end

  test "encode okp key to cbor" do
    key = Keys.OKP.generate(:sig)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-2] == %CBOR.Tag{tag: :bytes, value: key.x}
  end

  test "encode rsa key to map" do
    key = Keys.RSA.generate(:rs256)
    map = Keys.encode(key)

    assert map[-1] == key.n
    assert map[-2] == key.e
    refute Map.has_key?(map, -3)
  end

  test "encode rsa key to cbor" do
    key = Keys.RSA.generate(:rs256)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-1] == key.n
    assert map[-2] == key.e
  end

  test "encode headers" do
    assert Headers.translate(%{alg: :eddsa}) == %{1 => -8}
    assert Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

    assert Headers.tag_phdr(%{alg: :eddsa}) == COSE.tag_as_byte(<<0xA1, 0x01, 0x27>>)
    phdr = Headers.tag_phdr(%{alg: :eddsa})
    assert Headers.decode_phdr(phdr) == {:ok, %{alg: :eddsa}}
  end

  test "decode_phdr/1 rejects malformed protected headers" do
    for phdr <- [
          %{1 => -8},
          5,
          "text",
          COSE.tag_as_byte(<<>>),
          COSE.tag_as_byte(CBOR.encode([1])),
          COSE.tag_as_byte(CBOR.encode(%{1 => -8}) <> <<0>>),
          COSE.tag_as_byte(CBOR.encode(%CBOR.Tag{tag: 1, value: 3})),
          COSE.tag_as_byte(<<0x1C>>)
        ] do
      assert Headers.decode_phdr(phdr) == {:error, :malformed_message}
    end
  end

  test "safe_translate_back/1 translates a plain map" do
    iv = COSE.tag_as_byte(<<1, 2, 3>>)

    assert Headers.safe_translate_back(%{1 => -8, 5 => iv, 99 => 1}) ==
             {:ok, %{99 => 1, alg: :eddsa, iv: iv}}
  end

  test "safe_translate_back/1 rejects values that are not plain maps" do
    for hdr <- [
          7,
          nil,
          "text",
          [1, 2],
          [{1, -8}],
          %CBOR.Tag{tag: 1, value: 3},
          COSE.tag_as_byte(<<1>>),
          ~U[2020-01-01 00:00:00Z]
        ] do
      assert Headers.safe_translate_back(hdr) == {:error, :malformed_message}
    end
  end
end
