# Evidence class: SYNTHETIC unexecuted research trainer source; no model results.
"""New isolated Gen16 protocol. Never imports or executes the recovered trainer."""
import argparse
import json
import math
import os
from pathlib import Path
import signal
import sys

from runner_core import (Guard, Interrupted, Refused, require, run_session,
                         validate_manifest, write_json, row_sha)


class CudaBackend:
    def __init__(self, context, guard):
        # Only reached after registration, hashes, conditional readiness and supervisor checks.
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
        self.torch, self.context, self.guard = torch, context, guard
        m = context["manifest"]
        require(torch.cuda.is_available(), "Registered CUDA device unavailable")
        require(torch.version.cuda == m["runtime"]["cuda_version"], "Actual CUDA version differs from lock")
        self.device = torch.device(m["runtime"]["device"])
        torch.manual_seed(m["training"]["seed"])
        torch.cuda.reset_peak_memory_stats(self.device)
        guard.check()
        self.tokenizer = AutoTokenizer.from_pretrained(str(context["roots"]["tokenizer"]),
                              local_files_only=True, trust_remote_code=False)
        guard.check()
        model = AutoModelForCausalLM.from_pretrained(str(context["roots"]["base_model"]),
                    local_files_only=True, trust_remote_code=False, use_safetensors=True,
                    torch_dtype=torch.bfloat16, device_map={"": str(self.device)})
        guard.check()
        configured_context = getattr(model.config, "max_position_embeddings", None)
        if configured_context is None:
            configured_context = getattr(getattr(model.config, "text_config", None), "max_position_embeddings", None)
        self.context_limit = m["runtime"]["qualified_context_tokens"]
        require(type(configured_context) is int and 0 < self.context_limit <= configured_context,
                "Qualified context capacity exceeds or lacks model-config support")
        model.config.use_cache = False
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        self.model = PeftModel.from_pretrained(model, str(context["roots"]["parent_adapter"]),
                                              is_trainable=True, local_files_only=True)
        guard.check()
        parameters = [p for p in self.model.parameters() if p.requires_grad]
        require(parameters, "Continuation has no trainable parameters")
        self.optimizer = torch.optim.AdamW(parameters, lr=m["training"]["lr"],
                                          betas=(0.9, 0.999), eps=1e-8, weight_decay=0.01)
        self.scheduler = torch.optim.lr_scheduler.LambdaLR(self.optimizer, lambda epoch: 0.8 ** epoch)
        self.model.train()
        self.evaluation_number = 0

    def prepare(self, context, guard):
        torch, tok = self.torch, self.tokenizer
        cap = context["manifest"]["training"]["max_tokens"]
        self.examples, self.prefixes = {}, []
        for kind, key in [("corpus", "corpus_rows"), ("engraving", "engraving_rows")]:
            examples = []
            for row in context["paths"][key]:
                guard.check()
                chosen = row.get("chosen", row.get("completion"))
                messages = [{"role": "user", "content": row["prompt"]},
                            {"role": "assistant", "content": chosen}]
                text = tok.apply_chat_template(messages, tokenize=False)
                ids = tok(text, truncation=False, return_tensors="pt").input_ids[0]
                prefix_text = tok.apply_chat_template(messages[:1], tokenize=False, add_generation_prompt=True)
                prefix = tok(prefix_text, truncation=False).input_ids
                require(len(ids) <= min(cap, self.context_limit) and len(prefix) <= cap,
                        "Truncation/context overflow would change registered target; refused")
                require(len(prefix) < len(ids), "No assistant-target tokens available")
                require(ids[:len(prefix)].tolist() == prefix, "Chat-template/tokenizer prefix alignment differs; no masking assumption")
                labels = ids.clone()
                labels[:len(prefix)] = -100
                require((labels[1:] != -100).any().item(), "No shifted assistant-target loss tokens")
                examples.append((ids, labels))
                if kind == "engraving":
                    require(len(prefix) + context["manifest"]["metrics"]["max_new_tokens"] <= self.context_limit,
                            "Generation prefix plus token budget exceeds qualified context capacity")
                    target = chosen.strip()[:240]
                    target_ids = tok(target, add_special_tokens=False).input_ids
                    needed = len(target_ids)
                    require(target and 0 < needed <= 120, "Required character prefix exceeds generation cap")
                    require(tok.decode(target_ids, skip_special_tokens=False, clean_up_tokenization_spaces=False) == target,
                            "Required prefix does not round-trip under registered decoder")
                    self.prefixes.append({"ids": prefix, "target": target,
                                          "target_tokens": needed, "row_sha256": row_sha(row)})
                guard.check()
            self.examples[kind] = examples
        require([p["target_tokens"] for p in self.prefixes] == context["baseline"]["target_prefix_tokens"],
                "Actual prefix tokenization differs from registered baseline")

    def train_one(self, kind, row):
        ids, labels = self.examples[kind][row]
        self.model.train()
        result = self.model(input_ids=ids[None].to(self.device), labels=labels[None].to(self.device))
        loss = float(result.loss.detach().item())
        require(math.isfinite(loss), "Nonfinite model loss")
        result.loss.backward()
        self.optimizer.step()
        self.optimizer.zero_grad(set_to_none=True)
        return loss

    def complete_epoch(self):
        self.scheduler.step()

    def evaluate(self, check):
        # Guard object and callable ticks share this interface without importing model code in tests.
        tick = check.check if hasattr(check, "check") else check
        torch, tok = self.torch, self.tokenizer
        was_training = self.model.training
        self.model.eval()
        rows = []
        self.evaluation_number += 1
        try:
            with torch.no_grad():
                for index, prefix in enumerate(self.prefixes):
                    tick()
                    ids, labels = self.examples["engraving"][index]
                    result = self.model(input_ids=ids[None].to(self.device), labels=labels[None].to(self.device))
                    loss = float(result.loss.detach().item())
                    prompt_ids = torch.tensor(prefix["ids"], dtype=torch.long, device=self.device)[None]
                    generated = self.model.generate(prompt_ids, max_new_tokens=120, do_sample=False)
                    decoded = tok.decode(generated[0][len(prefix["ids"]):],
                                         skip_special_tokens=False, clean_up_tokenization_spaces=False)
                    rows.append({"row": index, "loss": loss,
                                 "strict_recall": decoded.strip().startswith(prefix["target"]),
                                 "legacy_substring_diagnostic": prefix["target"] in decoded,
                                 "generated": decoded, "row_content_sha256": prefix["row_sha256"]})
                    write_json(self.context["output"] / ("evaluation-" + str(self.evaluation_number) + "-row-" + str(index) + ".json"),
                               {**rows[-1], "checkpoint_binding": "UNBOUND_UNTIL_GATE_CHECKPOINT_SAVED", "partial_evaluation_group": True})
                    tick()
        finally:
            self.model.train(was_training)
        return {"rows": rows, "loss_metric": "all-seven assistant-target eval loss",
                "recall_metric": "strict Unicode character prefix, not complete-answer or byte equality",
                "peak_cuda_allocated_bytes": torch.cuda.max_memory_allocated(self.device),
                "peak_cuda_reserved_bytes": torch.cuda.max_memory_reserved(self.device)}

    def save(self, checkpoint, tick):
        temporary = checkpoint.with_name(checkpoint.name + ".partial")
        require(not checkpoint.exists() and not temporary.exists(), "Refusing an existing checkpoint path")
        temporary.mkdir(mode=0o700)
        write_json(temporary / "artifact-label.json", {"kind": "adapter-only binary sidecar", "status": "PARTIAL_UNTIL_RENAME"})
        tick()
        self.model.save_pretrained(str(temporary), safe_serialization=True)
        tick()
        temporary.rename(checkpoint)


def main(argv=None):
    # Starts before argument parsing, hash validation, imports, loading and encoding.
    guard = Guard()
    parser = argparse.ArgumentParser(description="Isolated reference-only Gen16 runner; no provider control")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    print("Evidence class: MEASURED runner control telemetry; model outputs exist only if explicitly executed.", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Interrupted("SIGTERM from supervisor")))
    try:
        manifest_path = Path(args.manifest)
        require(manifest_path.stat().st_size <= 4 * 1024 * 1024, "Manifest exceeds input size bound")
        context = validate_manifest(manifest_path.read_bytes(), args.manifest_sha256, guard, execute=args.execute)
        context["command_argv"] = [sys.executable, str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)]
        if args.validate_only:
            print(json.dumps({"status": "INPUT_BINDINGS_VALIDATED_ONLY", "model_loaded": False,
                              "provider_action": False, "output_created": False,
                              "actual_model_resource_or_stop_qualification": "Not established by this command"}))
            return 0
        outcome = run_session(context, guard, CudaBackend)
        print(json.dumps(outcome))
        return 0 if outcome["status"] == "PASS" and outcome.get("local_export_hashes_complete") and not outcome.get("local_finalization_errors") else 2
    except (Refused, Interrupted, KeyboardInterrupt, Exception) as error:
        # Preflight refusal cannot write into an existing output. Supervisor retains this stdout.
        print(json.dumps({"status": "INCOMPLETE" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "REFUSED",
                          "error_type": type(error).__name__, "reason": str(error),
                          "model_start_authorized_by_this_result": False,
                          "failure_export": "Supervisor must retain stdout; no existing output modified",
                          "provider_action": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
