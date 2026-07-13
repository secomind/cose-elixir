defmodule COSETest.ECCKey do
  use ExUnit.Case

  alias COSE.Keys.ECC

  @kty 1
  @crv -1
  @x -2
  @y -3

  describe "ECC.decode/1" do
    test "accepts a valid P-256 COSE_Key map" do
      key = ECC.generate(:es256)
      cbor_map = %{@kty => 2, @crv => 1, @x => key.x, @y => key.y}

      assert {:ok, parsed} = ECC.decode(cbor_map)
      assert parsed.kty == :ecc
      assert parsed.crv == :p256
      assert parsed.alg == :es256
      assert parsed.x == key.x
      assert parsed.y == key.y
    end

    test "rejects coordinate of wrong size" do
      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => :binary.copy(<<0>>, 31),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = ECC.decode(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = ECC.decode(%{})
    end

    test "is exported" do
      assert function_exported?(ECC, :decode, 1)
    end

    test "accepts a P-256 map with tag-wrapped coordinates" do
      key = ECC.generate(:es256)

      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => %CBOR.Tag{tag: :bytes, value: key.x},
        @y => %CBOR.Tag{tag: :bytes, value: key.y}
      }

      assert COSE.Keys.decode(cbor_map) ==
               {:ok, %ECC{kty: :ecc, crv: :p256, alg: :es256, x: key.x, y: key.y}}
    end

    test "accepts a P-256 map with raw-binary coordinates" do
      key = ECC.generate(:es256)
      cbor_map = %{@kty => 2, @crv => 1, @x => key.x, @y => key.y}

      assert COSE.Keys.decode(cbor_map) ==
               {:ok, %ECC{kty: :ecc, crv: :p256, alg: :es256, x: key.x, y: key.y}}
    end

    test "rejects an unknown kty" do
      assert {:error, :invalid_cose_key} = COSE.Keys.decode(%{@kty => 99})
    end

    test "rejects an unsupported crv" do
      cbor_map = %{
        @kty => 2,
        @crv => 99,
        @x => :binary.copy(<<0>>, 32),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = COSE.Keys.decode(cbor_map)
    end

    test "rejects a coordinate of the wrong length" do
      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => :binary.copy(<<0>>, 31),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = COSE.Keys.decode(cbor_map)
    end
  end
end
