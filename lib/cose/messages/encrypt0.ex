defmodule COSE.Messages.Encrypt0 do
  defstruct [:phdr, :uhdr, :ciphertext, :payload, :aad]

  @tag_length 16

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
      :crypto.crypto_one_time_aead(cipher_suite, key.k, iv, msg.payload, aad, @tag_length, true)

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

  @spec decrypt_decode(binary, :crypto.cipher_aead(), map) ::
          {:ok, %__MODULE__{}}
          | {:error, :malformed_message | :invalid_key | :decryption_failed | atom}
  def decrypt_decode(msg_cbor, cipher_suite, key) do
    with {:ok, msg} <- decode_cbor(msg_cbor) do
      decrypt(msg, cipher_suite, key, msg.uhdr.iv.value)
    end
  end

  @spec decrypt(%__MODULE__{}, :crypto.cipher_aead(), map, binary, binary) ::
          {:ok, %__MODULE__{}}
          | {:error, :malformed_message | :invalid_key | :decryption_failed}
  def decrypt(msg, cipher_suite, key, iv, external_aad \\ <<>>) do
    cipher_info = :crypto.cipher_info(cipher_suite)

    with :ok <- validate_key(key, cipher_info),
         :ok <- validate_iv(iv, cipher_info) do
      aad = msg |> enc_structure(external_aad) |> CBOR.encode()
      {encrypted, tag} = split_encrypted_tag(msg.ciphertext.value, @tag_length)

      :crypto.crypto_one_time_aead(cipher_suite, key.k, iv, encrypted, aad, tag, false)
      |> case do
        payload when is_binary(payload) ->
          {:ok, Map.put(msg, :payload, payload)}

        :error ->
          {:error, :decryption_failed}
      end
    end
  end

  @spec decode_cbor(binary) :: {:ok, %__MODULE__{}} | {:error, :malformed_message | atom}
  def decode_cbor(encoded_msg) do
    with {:ok, decoded, _} <- CBOR.decode(encoded_msg) do
      decode(decoded)
    end
  end

  @spec decode(term) :: {:ok, %__MODULE__{}} | {:error, :malformed_message}
  def decode(%CBOR.Tag{tag: 16, value: [phdr, uhdr, ciphertext]}) do
    with {:ok, phdr} <- COSE.Headers.decode_phdr(phdr),
         {:ok, uhdr} <- COSE.Headers.safe_translate_back(uhdr),
         :ok <- validate_iv_header(uhdr),
         :ok <- validate_ciphertext(ciphertext) do
      {:ok, %__MODULE__{phdr: phdr, uhdr: uhdr, ciphertext: ciphertext}}
    end
  end

  def decode(_msg), do: {:error, :malformed_message}

  def enc_structure(msg, external_aad \\ <<>>) do
    [
      "Encrypt0",
      (msg.phdr == %{} && COSE.tag_as_byte(<<>>)) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad)
    ]
  end

  def split_encrypted_tag(ciphertext, tag_len \\ @tag_length) do
    encrypted_len = byte_size(ciphertext) - tag_len
    <<encrypted::binary-size(encrypted_len), tag::binary-size(tag_len)>> = ciphertext
    {encrypted, tag}
  end

  defp validate_iv_header(%{iv: %CBOR.Tag{tag: :bytes}}), do: :ok
  defp validate_iv_header(_uhdr), do: {:error, :malformed_message}

  defp validate_ciphertext(%CBOR.Tag{tag: :bytes, value: ciphertext})
       when byte_size(ciphertext) >= @tag_length,
       do: :ok

  defp validate_ciphertext(_ciphertext), do: {:error, :malformed_message}

  defp validate_key(%{k: k}, %{key_length: key_length}) when byte_size(k) == key_length, do: :ok
  defp validate_key(_key, _cipher_info), do: {:error, :invalid_key}

  defp validate_iv(iv, %{iv_length: iv_length}) when byte_size(iv) == iv_length, do: :ok
  defp validate_iv(_iv, _cipher_info), do: {:error, :malformed_message}
end
