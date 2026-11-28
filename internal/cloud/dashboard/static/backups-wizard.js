// Guided setup of the backup destination (Admin -> Backups, first time only).
//
// The server renders one plain POST form with four visible sections and a
// single "Save destination" submit, so the page works without this script.
// The script only enhances it: one step at a time with Back / Next, the
// required fields of a step checked before moving on, aria-current on the
// active step, focus on the step heading, a running summary, the provider
// hint and placeholders following the provider select, and "Test
// connection", which asks the check route (through htmx) about the submitted
// fields without saving them. It never stores, logs or displays a credential;
// the summary only says whether both keys are filled in.
(function () {
	"use strict";

	function each(list, fn) {
		Array.prototype.forEach.call(list, fn);
	}

	function normalizedPrefix(value) {
		var segments = value.trim().split("/").filter(function (s) {
			return s !== "";
		});
		return segments.length ? segments.join("/") + "/" : "";
	}

	function init() {
		var form = document.querySelector("form[data-backup-wizard]");
		if (!form || form.getAttribute("data-wizard-ready") === "true") {
			return;
		}
		form.setAttribute("data-wizard-ready", "true");

		var steps = Array.prototype.slice.call(form.querySelectorAll("[data-wizard-step]"));
		var items = form.querySelectorAll("[data-wizard-stepper-item]");
		var result = form.querySelector("#backup-wizard-result");
		var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
		var total = steps.length;
		var current = 1;

		// Each step is checked by the script, so a required field in a hidden
		// step never blocks the submit without telling the admin why.
		form.noValidate = true;
		form.classList.add("is-stepped");
		each(form.querySelectorAll("[data-wizard-next], [data-wizard-back], [data-wizard-check], [data-wizard-js-only]"), function (el) {
			el.hidden = false;
		});
		each(form.querySelectorAll("[data-wizard-stepper-sub]"), function (sub) {
			sub.setAttribute("data-default", sub.textContent);
		});

		function field(name) {
			var el = form.elements.namedItem(name);
			return el && typeof el.value === "string" ? el : null;
		}

		function value(name) {
			var el = field(name);
			return el ? el.value.trim() : "";
		}

		// pickedProvider is the selected option of the provider select.
		function pickedProvider() {
			var select = form.querySelector('select[name="provider"]');
			return select && select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
		}

		function firstInvalid(n) {
			var fields = steps[n - 1].querySelectorAll("input, select, textarea");
			for (var i = 0; i < fields.length; i++) {
				if (!fields[i].checkValidity()) {
					return fields[i];
				}
			}
			return null;
		}

		function setSummary(name, text) {
			var dd = form.querySelector('[data-wizard-summary="' + name + '"]');
			if (!dd) {
				return;
			}
			dd.textContent = text || dd.getAttribute("data-pending");
			dd.classList.toggle("is-pending", !text);
		}

		function setStepSub(n, text) {
			var sub = form.querySelector('[data-wizard-stepper-sub="' + n + '"]');
			if (sub) {
				sub.textContent = text || sub.getAttribute("data-default");
			}
		}

		function refresh() {
			var provider = pickedProvider();
			var providerName = provider ? provider.textContent.trim() : "";
			if (provider) {
				each(form.querySelectorAll("[data-provider-hint]"), function (hint) {
					hint.hidden = hint.getAttribute("data-provider-hint") !== provider.value;
				});
				var endpoint = field("endpoint");
				var region = field("region");
				if (endpoint) {
					endpoint.placeholder = provider.getAttribute("data-endpoint-placeholder");
				}
				if (region) {
					region.placeholder = provider.getAttribute("data-region-placeholder");
				}
			}
			var bucket = value("bucket");
			var prefix = normalizedPrefix(value("prefix"));
			var keys = value("access_key_id") !== "" && value("secret_access_key") !== "";

			setSummary("provider", providerName);
			setSummary("endpoint", value("endpoint"));
			setSummary("region", value("region"));
			setSummary("bucket", bucket);
			setSummary("prefix", prefix);
			setSummary("keys", keys ? "both entered" : "");

			setStepSub(1, providerName);
			setStepSub(2, bucket ? bucket + "/" + prefix : "");
			setStepSub(3, keys ? "both entered" : "");

			each(form.querySelectorAll(".backup-path-bucket"), function (el) {
				el.textContent = bucket || "<bucket>";
			});
			each(form.querySelectorAll(".backup-path-prefix"), function (el) {
				el.textContent = prefix;
			});
		}

		function show(n, focus) {
			current = Math.min(Math.max(n, 1), total);
			steps.forEach(function (step, i) {
				step.hidden = i + 1 !== current;
			});
			each(items, function (item) {
				var k = parseInt(item.getAttribute("data-wizard-stepper-item"), 10);
				if (k === current) {
					item.setAttribute("aria-current", "step");
				} else {
					item.removeAttribute("aria-current");
				}
				item.classList.toggle("is-done", k < current);
			});
			refresh();
			if (focus) {
				var heading = steps[current - 1].querySelector(".backup-step-title");
				if (heading) {
					heading.focus({ preventScroll: true });
					heading.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "nearest" });
				}
			}
		}

		// stopAtInvalid opens the first step before `upTo` with an invalid
		// field and reports it; it returns true when it did.
		function stopAtInvalid(upTo) {
			for (var k = 1; k < upTo; k++) {
				var bad = firstInvalid(k);
				if (bad) {
					show(k, false);
					bad.reportValidity();
					return true;
				}
			}
			return false;
		}

		function goTo(n) {
			if (n > current && stopAtInvalid(n)) {
				return;
			}
			show(n, true);
		}

		form.addEventListener("click", function (event) {
			var target = event.target.closest("[data-wizard-goto], [data-wizard-next], [data-wizard-back], [data-wizard-check]");
			if (!target || !form.contains(target)) {
				return;
			}
			if (target.hasAttribute("data-wizard-goto")) {
				event.preventDefault();
				goTo(parseInt(target.getAttribute("data-wizard-goto"), 10));
			} else if (target.hasAttribute("data-wizard-next")) {
				goTo(current + 1);
			} else if (target.hasAttribute("data-wizard-back")) {
				show(current - 1, true);
			} else if (target.hasAttribute("data-wizard-check")) {
				event.preventDefault();
				if (stopAtInvalid(total) || !window.htmx) {
					return;
				}
				if (result) {
					result.textContent = "Testing the connection…";
				}
				window.htmx.trigger(target, "backup-wizard-check");
			}
		});

		form.addEventListener("submit", function (event) {
			if (stopAtInvalid(total + 1)) {
				event.preventDefault();
			}
		});

		form.addEventListener("input", refresh);
		form.addEventListener("change", refresh);

		function checkFailed() {
			if (result) {
				result.textContent = "The connection test could not run. Try again.";
			}
		}
		form.addEventListener("htmx:responseError", checkFailed);
		form.addEventListener("htmx:sendError", checkFailed);

		var start = parseInt(form.getAttribute("data-wizard-start"), 10) || 1;
		show(start, start !== 1);
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
