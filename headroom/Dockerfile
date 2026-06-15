FROM python:3.12-slim
RUN pip install --no-cache-dir 'headroom-ai[proxy]'

# ORT auto-detects all physical CPUs and tries to pin threads via sched_setaffinity.
# In a Proxmox LXC with a restricted cpuset the masks are invalid (EINVAL flood).
# Patch create_cpu_session_options to default to 1 thread, skipping affinity entirely.
RUN python3 -c "import headroom.onnx_runtime as m, inspect, pathlib; src = pathlib.Path(inspect.getfile(m)); txt = src.read_text().replace('    if intra_op_num_threads is not None:\n        sess_options.intra_op_num_threads = intra_op_num_threads\n    if inter_op_num_threads is not None:\n        sess_options.inter_op_num_threads = inter_op_num_threads', '    sess_options.intra_op_num_threads = intra_op_num_threads if intra_op_num_threads is not None else 1\n    sess_options.inter_op_num_threads = inter_op_num_threads if inter_op_num_threads is not None else 1'); src.write_text(txt); print('Patched', src)"
# Magika creates its own InferenceSession with no SessionOptions — same affinity issue.
RUN python3 -c "import magika.magika as m, inspect, pathlib; src = pathlib.Path(inspect.getfile(m)); txt = src.read_text().replace('        onnx_session = rt.InferenceSession(\n            self._model_path,\n            providers=[\"CPUExecutionProvider\"],\n        )', '        _opts = rt.SessionOptions()\n        _opts.intra_op_num_threads = 1\n        _opts.inter_op_num_threads = 1\n        onnx_session = rt.InferenceSession(\n            self._model_path,\n            _opts,\n            providers=[\"CPUExecutionProvider\"],\n        )'); src.write_text(txt); print('Patched', src)"

EXPOSE 8787
CMD ["headroom", "proxy", "--host", "0.0.0.0", "--stateless", "--no-telemetry"]
