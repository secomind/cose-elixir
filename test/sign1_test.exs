defmodule COSETest.Sign1 do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Messages}
  alias Messages.{Sign1}

  describe "sign1 message" do
    setup do
      d = Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21")
      x = Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324")

      okp_key = Keys.OKP.generate(:sig)
      okp_key = Map.put(okp_key, :d, d) |> Map.put(:x, x)

      ecc_key = Keys.ECC.generate(:es256)
      rsa_key = Keys.RSA.generate(:rs384)

      msg = Sign1.build("content to sign", %{alg: :eddsa})
      {:ok, %{okp_key: okp_key, ecc_key: ecc_key, rsa_key: rsa_key, msg: msg}}
    end

    test "sign with okp", %{okp_key: key, msg: msg} do
      msg = Sign1.sign(msg, key)
      assert Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute Sign1.verify(altered_msg, key)
    end

    test "sign with ecc", %{ecc_key: key, msg: msg} do
      msg = Sign1.sign(msg, key)
      assert Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute Sign1.verify(altered_msg, key)
    end

    test "sign with rsa", %{rsa_key: key, msg: msg} do
      msg = Sign1.sign(msg, key)
      assert Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute Sign1.verify(altered_msg, key)
    end

    test "encode with okp", %{okp_key: key, msg: msg} do
      encoded_msg = Sign1.sign_encode_cbor(msg, key)
      {:ok, verified_msg} = Messages.Sign1.verify_decode(encoded_msg, key)
      assert verified_msg == Sign1.sign(msg, key)
    end

    test "encode with ecc", %{ecc_key: key, msg: msg} do
      encoded_msg = Sign1.sign_encode_cbor(msg, key)
      {:ok, verified_msg} = Messages.Sign1.verify_decode(encoded_msg, key)

      # signature could be different
      fields = [:payload, :phdr, :uhdr]
      assert Map.take(verified_msg, fields) == Sign1.sign(msg, key) |> Map.take(fields)
    end

    test "encode with rsa", %{rsa_key: key, msg: msg} do
      encoded_msg = Sign1.sign_encode_cbor(msg, key)
      {:ok, verified_msg} = Messages.Sign1.verify_decode(encoded_msg, key)
      assert verified_msg == Sign1.sign(msg, key)
    end
  end
end
