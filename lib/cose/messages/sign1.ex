defmodule COSE.Messages.Sign1 do
  alias COSE.Keys

  defstruct [:phdr, :uhdr, :payload, :signature]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{phdr: phdr, uhdr: uhdr, payload: COSE.tag_as_byte(payload)}
  end

  def sign_encode(msg, key, digest_type \\ nil) do
    with {:ok, msg} <- sign(msg, key, digest_type) do
      value = [
        COSE.Headers.tag_phdr(msg.phdr),
        msg.uhdr,
        msg.payload,
        msg.signature
      ]

      result = %CBOR.Tag{tag: 18, value: value}
      {:ok, result}
    end
  end

  def sign_encode_cbor(msg, key, digest_type \\ nil) do
    with {:ok, signed} <- sign_encode(msg, key, digest_type) do
      encoded = CBOR.encode(signed)
      {:ok, encoded}
    end
  end

  def sign(msg, key, digest_type \\ nil, external_aad \\ <<>>) do
    digest_type = digest_type(msg, digest_type)
    to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

    with {:ok, signature} <- Keys.sign(key, digest_type, to_be_signed) do
      msg = %{msg | signature: COSE.tag_as_byte(signature)}
      {:ok, msg}
    end
  end

  def verify_decode(encoded_msg, key) do
    with {:ok, msg} <- decode_cbor(encoded_msg),
         :ok <- verify(msg, key) do
      {:ok, msg}
    end
  end

  def decode_cbor(encoded_msg) do
    with {:ok, decoded, _} <- CBOR.decode(encoded_msg) do
      decode(decoded)
    end
  end

  def decode(msg) do
    with %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]} <- msg,
         {:ok, phdr} <- COSE.Headers.decode_phdr(phdr) do
      msg =
        %__MODULE__{
          phdr: phdr,
          uhdr: uhdr,
          payload: payload,
          signature: signature
        }

      {:ok, msg}
    else
      _ -> :error
    end
  end

  def verify(msg, ver_key, digest_type \\ nil, external_aad \\ <<>>) do
    to_be_verified = CBOR.encode(sig_structure(msg, external_aad))
    %CBOR.Tag{tag: :bytes, value: signature} = msg.signature
    digest_type = digest_type(msg, digest_type)

    Keys.verify(ver_key, digest_type, to_be_verified, signature)
  end

  def sig_structure(msg, external_aad \\ <<>>) do
    [
      "Signature1",
      (msg.phdr == %{} && <<>>) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad),
      msg.payload
    ]
  end

  defp digest_type(msg, nil) do
    case Map.fetch!(msg.phdr, :alg) do
      :es256 -> :sha256
      :rs256 -> :sha256
      :ps256 -> :sha256
      :es384 -> :sha384
      :rs384 -> :sha384
      other -> other
    end
  end

  defp digest_type(_msg, digest), do: digest
end
