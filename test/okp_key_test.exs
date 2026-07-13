defmodule COSETest.OKPKey do
  use ExUnit.Case

  alias COSE.Keys.OKP

  @kty 1
  @crv -1
  @x -2

  describe "OKP.decode/1" do
    test "accepts a valid X25519 COSE_Key map" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => 1, @crv => 4, @x => key.x}

      assert {:ok, parsed} = OKP.decode(cbor_map)
      assert parsed.kty == :okp
      assert parsed.crv == :x25519
      assert parsed.x == key.x
    end

    test "rejects x coordinate of wrong size" do
      cbor_map = %{@kty => 1, @crv => 4, @x => :binary.copy(<<0>>, 31)}
      assert {:error, :invalid_cose_key} = OKP.decode(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = OKP.decode(%{})
    end

    test "is exported" do
      assert function_exported?(OKP, :decode, 1)
    end

    test "accepts a X25519 map with tag-wrapped x" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => 1, @crv => 4, @x => %CBOR.Tag{tag: :bytes, value: key.x}}

      assert COSE.Keys.decode(cbor_map) == {:ok, %OKP{kty: :okp, crv: :x25519, x: key.x}}
    end

    test "accepts a X25519 map with raw-binary x" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => 1, @crv => 4, @x => key.x}

      assert COSE.Keys.decode(cbor_map) == {:ok, %OKP{kty: :okp, crv: :x25519, x: key.x}}
    end

    test "rejects an unsupported crv" do
      cbor_map = %{@kty => 1, @crv => 99, @x => :binary.copy(<<0>>, 32)}
      assert {:error, :invalid_cose_key} = COSE.Keys.decode(cbor_map)
    end
  end
end
