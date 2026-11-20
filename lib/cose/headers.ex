defmodule COSE.Headers do
  def translate(phdr) do
    phdr
    |> Enum.map(fn {k, v} ->
      cond do
        k == :alg || k == 1 ->
          {COSE.header(k), COSE.algorithm(v)}

        true ->
          {COSE.header(k), v}
      end
    end)
    # FIXME: this may alter the order of the elements. TO-DO: think of a way to solve it.
    |> Enum.into(%{})
  end

  def translate_back(phdr) do
    phdr
    |> Enum.map(fn {k, v} ->
      cond do
        k == :alg || k == 1 ->
          {COSE.header_from_id(k), COSE.algorithm_from_id(v)}

        true ->
          {COSE.header_from_id(k), v}
      end
    end)
    # FIXME: this may alter the order of the elements. TO-DO: think of a way to solve it.
    |> Enum.into(%{})
  end

  def safe_translate_back(hdr) when is_map(hdr) and not is_struct(hdr),
    do: {:ok, translate_back(hdr)}

  def safe_translate_back(_hdr), do: {:error, :malformed_message}

  def tag_phdr(phdr_map) do
    COSE.tag_as_byte(CBOR.encode(translate(phdr_map)))
  end

  def decode_phdr(%CBOR.Tag{tag: :bytes, value: phdr_bytes}) do
    case CBOR.decode(phdr_bytes) do
      {:ok, phdr_map, ""} -> safe_translate_back(phdr_map)
      _ -> {:error, :malformed_message}
    end
  end

  def decode_phdr(_phdr), do: {:error, :malformed_message}
end
