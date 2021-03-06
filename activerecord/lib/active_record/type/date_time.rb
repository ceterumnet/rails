module ActiveRecord
  module Type
    class DateTime < Value # :nodoc:
      include TimeValue

      def type
        :datetime
      end

      private

      def cast_value(string)
        return string unless string.is_a?(::String)
        return if string.empty?

        fast_string_to_time(string) || fallback_string_to_time(string)
      end

      # '0.123456' -> 123456
      # '1.123456' -> 123456
      def microseconds(time)
        time[:sec_fraction] ? (time[:sec_fraction] * 1_000_000).to_i : 0
      end

      def fallback_string_to_time(string)
        time_hash = ::Date._parse(string)
        time_hash[:sec_fraction] = microseconds(time_hash)

        new_time(*time_hash.values_at(:year, :mon, :mday, :hour, :min, :sec, :sec_fraction, :offset))
      end
    end
  end
end
