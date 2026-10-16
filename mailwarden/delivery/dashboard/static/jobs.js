// Job alerts: keyboard shortcuts in Review and a live source filter in Browse.
// Progressive enhancement only: every action is a normal form or link and works without this file.
(function () {
  "use strict";

  function typing(target) {
    var tag = target && target.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (target && target.isContentEditable);
  }

  var review = document.getElementById("review");
  if (review) {
    document.addEventListener("keydown", function (event) {
      if (event.metaKey || event.ctrlKey || event.altKey || typing(event.target)) {
        return;
      }
      var key = event.key.toLowerCase();
      if (key === "j" && review.dataset.next) {
        window.location.assign(review.dataset.next);
      } else if (key === "k" && review.dataset.prev) {
        window.location.assign(review.dataset.prev);
      } else {
        var button = review.querySelector('[data-key="' + key + '"]');
        if (!button) {
          return;
        }
        event.preventDefault();
        button.click();
      }
    });
  }

  // Browse: narrow the source list as you type (the form still works without JS).
  document.querySelectorAll("input[data-filter]").forEach(function (input) {
    var list = document.querySelector(input.getAttribute("data-filter"));
    if (!list) {
      return;
    }
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      list.querySelectorAll("li").forEach(function (li) {
        if (li.querySelector("details")) {
          return;  // the "N more" group stays; its items are filtered below
        }
        li.hidden = q !== "" && li.textContent.toLowerCase().indexOf(q) === -1;
      });
      var more = list.querySelector("details");
      if (more && q !== "") {
        more.open = true;
      }
    });
  });

  // Close an open "..." menu when clicking elsewhere.
  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) {
        menu.open = false;
      }
    });
  });
})();
