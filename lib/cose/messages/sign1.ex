defmodule COSE.Messages.Sign1 do
  alias COSE.Keys

  defstruct [:phdr, :uhdr, :payload, :signature]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{phdr: phdr, uhdr: uhdr, payload: COSE.tag_as_byte(payload)}
  end

  def sign_encode(msg, key) do
    msg = sign(msg, key)

    value = [
      COSE.Headers.tag_phdr(msg.phdr),
      msg.uhdr,
      msg.payload,
      msg.signature
    ]

    %CBOR.Tag{tag: 18, value: value}
  end

  def sign_encode_cbor(msg, key) do
    sign_encode(msg, key)
    |> CBOR.encode()
  end

  def sign(msg, key, external_aad \\ <<>>) do
    to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

    signature =
      Keys.sign(key, to_be_signed)
      |> COSE.tag_as_byte()

    %__MODULE__{
      msg
      | signature: signature
    }
  end

  def verify_decode(encoded_msg, key) do
    with {:ok, msg} <- decode_cbor(encoded_msg) do
      if verify(msg, key) do
        {:ok, msg}
      else
        :error
      end
    end
  end

  def decode_cbor(encoded_msg) do
    with {:ok, decoded, _} <- CBOR.decode(encoded_msg) do
      decode(decoded)
    end
  end

  def decode(msg) do
    case msg do
      %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]} ->
        msg =
          %__MODULE__{
            phdr: COSE.Headers.decode_phdr(phdr),
            uhdr: uhdr,
            payload: payload,
            signature: signature
          }

        {:ok, msg}

      _ ->
        :error
    end
  end

  def verify(msg, ver_key, external_aad \\ <<>>) do
    to_be_verified = CBOR.encode(sig_structure(msg, external_aad))
    %CBOR.Tag{tag: :bytes, value: signature} = msg.signature

    if Keys.verify(ver_key, to_be_verified, signature) do
      msg
    else
      false
    end
  end

  def sig_structure(msg, external_aad \\ <<>>) do
    [
      "Signature1",
      (msg.phdr == %{} && <<>>) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad),
      msg.payload
    ]
  end
end
