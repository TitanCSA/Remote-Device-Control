  template<typename Packet>
  bool validate_fixed_input_packet(std::span<const std::uint8_t> packet, std::uint32_t declared_size) {
    constexpr auto expected_size = static_cast<std::uint32_t>(sizeof(Packet) - sizeof(std::uint32_t));
    if (declared_size != expected_size) {
      return false;
    }
    return packet.size() == sizeof(Packet);
  }

  /**
   * @brief Validate an input packet before any typed access or batching.
   *
   * @param packet Raw packet bytes.
   * @param parsed_header Optional destination for the safely copied packet header.
   * @return True when the packet is large enough for its declared and protocol-specific fields.
   */
  bool validate_input_packet(std::span<const std::uint8_t> packet, NV_INPUT_HEADER *parsed_header = nullptr) {
    if (packet.size() < sizeof(NV_INPUT_HEADER)) {
      return false;
    }

    NV_INPUT_HEADER header {};
    std::memcpy(&header, packet.data(), sizeof(header));
    if (parsed_header) {
      *parsed_header = header;
    }

    const auto declared_size = util::endian::big(header.size);
    if (declared_size < sizeof(header.magic) || declared_size != packet.size() - sizeof(header.size)) {
      return false;
    }

    switch (util::endian::little(header.magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        return validate_fixed_input_packet<NV_REL_MOUSE_MOVE_PACKET>(packet, declared_size);
      case MOUSE_MOVE_ABS_MAGIC:
        return validate_fixed_input_packet<NV_ABS_MOUSE_MOVE_PACKET>(packet, declared_size);
      case MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5:
      case MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5:
        return validate_fixed_input_packet<NV_MOUSE_BUTTON_PACKET>(packet, declared_size);
      case SCROLL_MAGIC_GEN5:
        return validate_fixed_input_packet<NV_SCROLL_PACKET>(packet, declared_size);
      case SS_HSCROLL_MAGIC:
        return validate_fixed_input_packet<SS_HSCROLL_PACKET>(packet, declared_size);
      case KEY_DOWN_EVENT_MAGIC:
      case KEY_UP_EVENT_MAGIC:
        return validate_fixed_input_packet<NV_KEYBOARD_PACKET>(packet, declared_size);
      case UTF8_TEXT_EVENT_MAGIC:
        return declared_size - sizeof(header.magic) <= UTF8_TEXT_EVENT_MAX_COUNT;
      case MULTI_CONTROLLER_MAGIC_GEN5:
        return validate_fixed_input_packet<NV_MULTI_CONTROLLER_PACKET>(packet, declared_size);
      case SS_TOUCH_MAGIC:
        return validate_fixed_input_packet<SS_TOUCH_PACKET>(packet, declared_size);
      case SS_PEN_MAGIC:
        return validate_fixed_input_packet<SS_PEN_PACKET>(packet, declared_size);
      case SS_CONTROLLER_ARRIVAL_MAGIC:
        return validate_fixed_input_packet<SS_CONTROLLER_ARRIVAL_PACKET>(packet, declared_size);
      case SS_CONTROLLER_TOUCH_MAGIC:
        return validate_fixed_input_packet<SS_CONTROLLER_TOUCH_PACKET>(packet, declared_size);
      case SS_CONTROLLER_MOTION_MAGIC:
        return validate_fixed_input_packet<SS_CONTROLLER_MOTION_PACKET>(packet, declared_size);
      case SS_CONTROLLER_BATTERY_MAGIC:
        return validate_fixed_input_packet<SS_CONTROLLER_BATTERY_PACKET>(packet, declared_size);
      default:
        return false;
    }
  }
