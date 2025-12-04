defmodule COSE.Messages.Encrypt0 do
  defstruct [:phdr, :uhdr, :ciphertext, :payload, :aad]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{
      phdr: phdr,
      uhdr: uhdr,
      payload: payload,
      aad: COSE.tag_as_byte(<<>>)
    }
  end

  def encrypt_encode(msg, cipher_suite, key, iv) do
    msg
    |> encrypt(cipher_suite, key, iv)
    |> encode_cbor()
  end

  def encrypt(msg, cipher_suite, key, iv, external_aad \\ <<>>) do
    aad = msg |> enc_structure(external_aad) |> CBOR.encode()

    {encrypted, tag} =
      :crypto.crypto_one_time_aead(cipher_suite, key.k, iv, msg.payload, aad, 8, true)

    Map.put(msg, :ciphertext, COSE.tag_as_byte(encrypted <> tag))
  end

  def encode_cbor(msg) do
    encode(msg)
    |> CBOR.encode()
  end

  def encode(msg) do
    cose_values = [
      COSE.Headers.tag_phdr(msg.phdr),
      COSE.Headers.translate(msg.uhdr),
      msg.ciphertext
    ]

    %CBOR.Tag{tag: 16, value: cose_values}
  end

  def decrypt_decode(msg_cbor, cipher_suite, key) do
    with {:ok, msg} <- decode_cbor(msg_cbor) do
      decrypt(msg, cipher_suite, key, msg.uhdr.iv.value)
    end
  end

  def decrypt(msg, cipher_suite, key, iv, external_aad \\ <<>>) do
    aad = msg |> enc_structure(external_aad) |> CBOR.encode()
    {encrypted, tag} = split_encrypted_tag(msg.ciphertext.value)

    :crypto.crypto_one_time_aead(cipher_suite, key.k, iv, encrypted, aad, tag, false)
    |> case do
      payload when is_binary(payload) ->
        {:ok, Map.put(msg, :payload, payload)}

      error ->
        error
    end
  end

  def decode_cbor(encoded_msg) do
    with {:ok, decoded, _} <- CBOR.decode(encoded_msg) do
      decode(decoded)
    end
  end

  def decode(msg) do
    with %CBOR.Tag{tag: 16, value: [phdr, uhdr, ciphertext]} <- msg,
         {:ok, phdr} <- COSE.Headers.decode_phdr(phdr) do
      decoded =
        %__MODULE__{
          phdr: phdr,
          uhdr: COSE.Headers.translate_back(uhdr),
          ciphertext: ciphertext
        }

      {:ok, decoded}
    else
      _ -> :error
    end
  end

  def enc_structure(msg, external_aad \\ <<>>) do
    [
      "Encrypt0",
      (msg.phdr == %{} && COSE.tag_as_byte(<<>>)) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad)
    ]
  end

  def split_encrypted_tag(ciphertext, tag_len \\ 8) do
    encrypted_len = byte_size(ciphertext) - tag_len
    <<encrypted::binary-size(encrypted_len), tag::binary-size(tag_len)>> = ciphertext
    {encrypted, tag}
  end
end
