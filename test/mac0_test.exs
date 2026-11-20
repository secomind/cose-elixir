defmodule COSETest.Mac0Test do
  use ExUnit.Case

  alias COSE.Headers
  alias COSE.Messages.Mac0
  alias COSE.Keys.Symmetric

  test "roundtrip" do
    msg_phdr = %{alg: :aes_ccm_16_64_128}

    msg_uhdr = %{
      iv: COSE.tag_as_byte(<<222, 100, 52, 107, 249, 208, 239, 101, 73, 73, 196, 224>>)
    }

    msg = Mac0.build("content to mac", msg_phdr, msg_uhdr)

    key = %Symmetric{k: <<0>>}

    encoded = Mac0.mac_encode(msg, :sha256, key)

    assert {:ok, decoded} = Mac0.verify_decode(encoded, :sha256, key)
    assert decoded.tag
    assert decoded.payload == msg.payload
  end

  test "rejects an unprotected header that is not a map" do
    phdr = Headers.tag_phdr(%{alg: :aes_ccm_16_64_128})

    for uhdr <- [7, [1, 2], %CBOR.Tag{tag: 1, value: 3}] do
      msg = %CBOR.Tag{
        tag: 17,
        value: [phdr, uhdr, COSE.tag_as_byte("content to mac"), COSE.tag_as_byte(<<0>>)]
      }

      assert {:error, :malformed_message} == Mac0.decode(CBOR.encode(msg))
    end
  end
end
