use PropCheck

defmodule State do
  def initial_state() do
    %{
      :crypto_init => false,
      :key_attributes_ptr => MbedTLS.psa_key_attributes_init(),
      :key_data => %KeyData{},
      # keys: {key_id , KeyData} list
      :keys => []
    }
  end
end
