defmodule COSE.Keys.RSA do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :pem_record, :n, :e, :d, :p, :q, :dp, :dq, :qi]

  @public_exponent 65_537

  @doc """
  Generates an RSA key pair for the given algorithm.
  Strict FDO Base Profile Support:
    - :rs256 -> 2048-bit key, SHA-256, PKCS#1 v1.5
    - :rs384 -> 3072-bit key, SHA-384, PKCS#1 v1.5
  """
  def generate(alg) do
    bits = bits(alg)

    {_pub, priv} =
      :crypto.generate_key(:rsa, {bits, @public_exponent})

    [e, n, d, p, q, dp, dq, qi] = priv

    %__MODULE__{
      kty: :rsa,
      alg: alg,
      n: n,
      e: e,
      d: d,
      p: p,
      q: q,
      dp: dp,
      dq: dq,
      qi: qi
    }
  end

  def from_record(pem_record) do
    {:RSAPrivateKey, _, n, e, d, p, q, dp, dq, qi, _} = pem_record

    alg =
      case modulus_bits(n) do
        2048 -> :rs256
        3072 -> :rs384
      end

    %__MODULE__{
      kty: :rsa,
      alg: alg,
      pem_record: pem_record,
      n: :binary.encode_unsigned(n),
      e: :binary.encode_unsigned(e),
      d: :binary.encode_unsigned(d),
      p: :binary.encode_unsigned(p),
      q: :binary.encode_unsigned(q),
      dp: :binary.encode_unsigned(dp),
      dq: :binary.encode_unsigned(dq),
      qi: :binary.encode_unsigned(qi)
    }
  end

  defp bits(:rs256), do: 2048
  defp bits(:rs384), do: 3072

  defp modulus_bits(modulus), do: modulus |> :binary.encode_unsigned() |> bit_size()
end

defimpl COSE.Keys.Key, for: COSE.Keys.RSA do
  def sign(key, digest_type, to_be_signed) do
    private_key =
      [key.e, key.n, key.d]

    :crypto.sign(:rsa, digest_type, to_be_signed, private_key, [])
  end

  def verify(key, digest_type, to_be_verified, signature) do
    public_key = [key.e, key.n]

    :crypto.verify(:rsa, digest_type, to_be_verified, signature, public_key, [])
  end
end
