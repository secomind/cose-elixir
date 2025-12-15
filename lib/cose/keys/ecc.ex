defmodule COSE.Keys.ECC do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :pem_record, :crv, :x, :y, :d]

  @doc """
  Generates a key for the specified algorithm.
  Supported: :es256 (P-256), :es384 (P-384)
  """
  def generate(alg) do
    {curve, cose_crv, key_len} = get_curve_info(alg)
    {pub, priv} = :crypto.generate_key(:ecdh, curve)

    <<4, x::binary-size(key_len), y::binary-size(key_len)>> = pub

    %__MODULE__{
      kty: :ecc,
      crv: cose_crv,
      alg: alg,
      x: x,
      y: y,
      d: priv
    }
  end

  def from_record(pem_record) do
    {:ECPrivateKey, _, priv_d, {:namedCurve, oid}, pub_bits, _} = pem_record

    alg = get_alg_from_oid(oid)
    {curve_erl, cose_crv, key_len} = get_curve_info(alg)

    final_pub =
      case pub_bits do
        :undefined ->
          {pub, _} = :crypto.generate_key(:ecdh, curve_erl, priv_d)
          pub

        val ->
          bitstring_to_binary(val)
      end

    case final_pub do
      <<4, x::binary-size(key_len), y::binary-size(key_len)>> ->
        %__MODULE__{
          kty: :ecc,
          crv: cose_crv,
          alg: alg,
          pem_record: pem_record,
          x: x,
          y: y,
          d: priv_d
        }

      _ ->
        raise "Compressed EC keys are not supported"
    end
  end

  def curve(key) do
    case key.alg do
      :es256 -> :secp256r1
      :es384 -> :secp384r1
    end
  end

  def key_size(key) do
    case key.alg do
      :es256 -> 32
      :es384 -> 48
    end
  end

  def public_key(key) do
    <<4, key.x::binary, key.y::binary>>
  end

  defp get_alg_from_oid({1, 2, 840, 10045, 3, 1, 7}), do: :es256
  defp get_alg_from_oid({1, 3, 132, 0, 34}), do: :es384

  defp get_curve_info(:es256), do: {:secp256r1, :p256, 32}
  defp get_curve_info(:es384), do: {:secp384r1, :p384, 48}

  defp bitstring_to_binary(val) when is_binary(val), do: val

  defp bitstring_to_binary(val) when is_bitstring(val) do
    size = bit_size(val)
    <<bin::binary-size(div(size, 8)), _::bitstring>> = val

    bin
  end
end

defimpl COSE.Keys.Key, for: COSE.Keys.ECC do
  alias COSE.Keys.ECC

  def sign(key, digest_type, to_be_signed) do
    curve = ECC.curve(key)

    der_signature = :crypto.sign(:ecdsa, digest_type, to_be_signed, [key.d, curve])

    key_size = ECC.key_size(key)
    der_to_raw(der_signature, key_size)
  end

  def verify(ver_key, digest_type, to_be_verified, raw_signature) do
    curve = ECC.curve(ver_key)
    pub_key_bin = ECC.public_key(ver_key)

    key_size = ECC.key_size(ver_key)

    case raw_to_der(raw_signature, key_size) do
      {:ok, der_signature} ->
        :crypto.verify(:ecdsa, digest_type, to_be_verified, der_signature, [pub_key_bin, curve])

      _ ->
        false
    end
  end

  def raw_to_der(raw_sig, key_size) do
    case raw_sig do
      <<r::binary-size(key_size), s::binary-size(key_size)>> ->
        (encode_integer(r) <> encode_integer(s))
        |> wrap_sequence()
        |> then(&{:ok, &1})

      _ ->
        :error
    end
  end

  defp wrap_sequence(content) do
    size = byte_size(content)
    <<0x30, size>> <> content
  end

  defp encode_integer(bin) do
    trimmed = trim_leading_zeros(bin)

    payload =
      case trimmed do
        <<b::8, _::binary>> when b >= 128 -> <<0x00>> <> trimmed
        <<>> -> <<0x00>>
        _ -> trimmed
      end

    size = byte_size(payload)
    <<0x02, size>> <> payload
  end

  defp trim_leading_zeros(<<0, rest::binary>>), do: trim_leading_zeros(rest)
  defp trim_leading_zeros(bin), do: bin

  def der_to_raw(der, key_size) do
    {r, s} = decode_der_sequence(der)

    pad_scalar(r, key_size) <> pad_scalar(s, key_size)
  end

  defp decode_der_sequence(
         <<0x30, _seq_len, 0x02, r_len, r::binary-size(r_len), 0x02, s_len,
           s::binary-size(s_len)>>
       ) do
    {r, s}
  end

  defp pad_scalar(bin, size) do
    clean_bin =
      case bin do
        <<0x00, rest::binary>> -> rest
        _ -> bin
      end

    pad_len = size - byte_size(clean_bin)

    if pad_len > 0 do
      <<0::size(pad_len)-unit(8)>> <> clean_bin
    else
      clean_bin
    end
  end
end
