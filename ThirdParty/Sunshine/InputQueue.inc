  // One scheduled worker per client, at most 256 protocol-sized packets.
  // Work in short batches so key-repeat/reset tasks cannot be starved by motion.
  void rdc_drain_input(std::shared_ptr<input_t> input) {
    for (unsigned count = 0; count < 32; ++count) {
      {
        std::lock_guard<std::mutex> lock(input->input_queue_lock);
        if (input->input_queue.empty()) {
          input->rdc_worker_scheduled = false;
          return;
        }
      }
      passthrough_next_message(input);
    }
    task_pool.push(rdc_drain_input, input);
  }

  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {
    if (!validate_input_packet(input_data)) return;
    bool schedule = false, overflow = false;
    {
      std::lock_guard<std::mutex> lock(input->input_queue_lock);
      if (input->input_queue.size() >= 256) {
        input->input_queue.clear();
        overflow = true;
      } else {
        input->input_queue.push_back(std::move(input_data));
        if (!input->rdc_worker_scheduled) schedule = input->rdc_worker_scheduled = true;
      }
    }
    // Dropping a release could leave a key held. End the session and remove
    // its owned Vdevice devices instead of silently losing state transitions.
    if (overflow) {
      BOOST_LOG(error) << "The remote input queue exceeded its safe bound; ending the session.";
      mail::man->event<bool>(mail::shutdown)->raise(true);
    } else if (schedule) task_pool.push(rdc_drain_input, input);
  }
