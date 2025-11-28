defmodule COSE.Messages.Mac0 do
  defstruct [:phdr, :uhdr, :payload, :tag]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{
      phdr: phdr,
      uhdr: uhdr,
      payload: payload,
      tag: nil
    }
  end

  def mac_encode(msg, digest_type, key, external_aad \\ <<>>) do
    msg
    |> compute_mac(digest_type, key, external_aad)
    |> encode()
  end

  def compute_mac(msg, digest_type, key, external_aad \\ <<>>) do
    # digest_type: :sha256 | :sha384

    to_be_maced =
      mac_structure(msg, external_aad)
      |> CBOR.encode()

    mac_value = :crypto.mac(:hmac, digest_type, key.k, to_be_maced)

    Map.put(msg, :tag, COSE.tag_as_byte(mac_value))
  end

  def verify_decode(encoded_msg, alg, key, external_aad \\ <<>>) do
    with {:ok, msg} <- decode(encoded_msg) do
      case verify(msg, alg, key, external_aad) do
        true -> {:ok, msg}
        false -> {:error, :integrity_check_failed}
      end
    end
  end

  def verify(msg, alg, key, external_aad \\ <<>>) do
    computed_msg = compute_mac(msg, alg, key, external_aad)

    compare(computed_msg.tag.value, msg.tag.value)
  end

  def to_message(msg) do
    cose_values = [
      COSE.Headers.tag_phdr(msg.phdr),
      COSE.Headers.translate(msg.uhdr),
      COSE.tag_as_byte(msg.payload),
      msg.tag
    ]

    %CBOR.Tag{tag: 17, value: cose_values}
  end

  def encode(msg) do
    to_message(msg)
    |> CBOR.encode()
  end

  def decode(encoded_msg) do
    with {:ok, decoded, _} <- CBOR.decode(encoded_msg) do
      from_message(decoded)
    end
  end

  def from_message(msg) do
    with %CBOR.Tag{tag: 17, value: [phdr, uhdr, payload_tag, tag]} <- msg,
         %CBOR.Tag{tag: :bytes, value: payload} <- payload_tag,
         {:ok, phdr} <- COSE.Headers.decode_phdr(phdr) do
      decoded =
        %__MODULE__{
          phdr: phdr,
          uhdr: COSE.Headers.translate_back(uhdr),
          payload: payload,
          tag: tag
        }

      {:ok, decoded}
    else
      _ -> :error
    end
  end

  def mac_structure(msg, external_aad \\ <<>>) do
    [
      "MAC0",
      (msg.phdr == %{} && COSE.tag_as_byte(<<>>)) || COSE.Headers.tag_phdr(msg.phdr),
      external_aad,
      COSE.tag_as_byte(msg.payload)
    ]
  end

  defp compare(left, right) do
    if byte_size(left) == byte_size(right) do
      :crypto.hash_equals(left, right)
    else
      false
    end
  end
end
