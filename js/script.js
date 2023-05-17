"use strict";

// VARIABLES -----------------------
var riskChart = document.getElementById("riskChart").getContext("2d");

const colors = [
  "rgb(176, 0, 4)", // Critical
  "rgb(230, 104, 38)", // High
  "rgb(247, 181, 10)", // Medium
  "rgb(46, 164, 63)", // Low
  "rgb(49, 160, 236)", // Info
];

const backgrounds = [
  "rgba(176, 0, 4, 0.5)", // Critical
  "rgba(230, 104, 38, 0.5)", // High
  "rgba(247, 181, 10, 0.5)", // Medium
  "rgba(46, 164, 63, 0.5)", // Low
  "rgba(49, 160, 236, 0.5)", // Info
];

const threats = [
  "Skills required",
  "Motive",
  "Opportunity",
  "Population Size",
  "Easy of Discovery",
  "Ease of Exploit",
  "Awareness",
  "Intrusion Detection",
  "Loss of confidentiality",
  "Loss of Integrity",
  "Loss of Availability",
  "Loss of Accountability",
  "Financial damage",
  "Reputation damage",
  "Non-Compliance",
  "Privacy violation",
];

const partials = [
  "sl",
  "m",
  "o",
  "s",
  "ed",
  "ee",
  "a",
  "id",
  "lc",
  "li",
  "lav",
  "lac",
  "fd",
  "rd",
  "nc",
  "pv",
];

const riskChartOptions = {
  legend: {
    position: "top",
    display: false,
  },
  title: {
    display: false,
    text: "OWASP Risk Matrix",
  },
  scale: {
    ticks: {
      beginAtZero: true,
      suggestedMin: 0,
      suggestedMax: 10,
      stepSize: 1,
    },
  },
};

// CHARTS -----------------------
riskChart = new Chart(riskChart, {
  type: "radar",
  data: {
    labels: [],
    datasets: [
      {
        data: [],
        pointBackgroundColor: "",
        backgroundColor: "",
        borderColor: "",
        borderWidth: 2,
      },
    ],
  },
  options: riskChartOptions,
});

updateRiskChart();

if (getUrlParameter("vector")) {
  loadVectors(getUrlParameter("vector"));
}

// FUNCTIONS -----------------------
function loadVectors(vector) {
  vector = vector.replace("(", "").replace(")", "");
  var values = vector.split("/");

  if (values.length == 16) {
    for (let i = 0; i < values.length; i++) {
      let aux = values[i].split(":");
      let vector = aux[1];
      console.log(vector);
      $("#" + partials[i].toLowerCase()).val(vector);
    }
  } else {
    swal(
      "Hey!!",
      "The vector is not correct, make sure you have copied correctly",
      "error"
    );
  }

  calculate();
}

function calculate() {
  var LS = 0;
  var TIS = 0;
  var BIS = 0;
  var dataset = [];
  var score = "";
  deleteClass();

  // Get values THREAT AGENT FACTORS and VULNERABILITY FACTORS
  LS =
    +$("#sl").val() +
    +$("#m").val() +
    +$("#o").val() +
    +$("#s").val() +
    +$("#ed").val() +
    +$("#ee").val() +
    +$("#a").val() +
    +$("#id").val() +
    0;
  dataset.push($("#sl").val());
  dataset.push($("#m").val());
  dataset.push($("#o").val());
  dataset.push($("#s").val());
  dataset.push($("#ed").val());
  dataset.push($("#ee").val());
  dataset.push($("#a").val());
  dataset.push($("#id").val());

  // Get values TECHNICAL IMPACT FACTORS and BUSINESS IMPACT FACTORS
  TIS = +$("#lc").val() + +$("#li").val() + +$("#lav").val() + +$("#lac").val();
  BIS = +$("#fd").val() + +$("#rd").val() + +$("#nc").val() + +$("#pv").val();

  dataset.push($("#lc").val());
  dataset.push($("#li").val());
  dataset.push($("#lav").val());
  dataset.push($("#lac").val());
  dataset.push($("#fd").val());
  dataset.push($("#rd").val());
  dataset.push($("#nc").val());
  dataset.push($("#pv").val());

  var LS = (LS / 8).toFixed(3);

  TIS = (TIS / 4).toFixed(3);
  BIS = (BIS / 4).toFixed(3);

  var FLS = getRisk(LS);
  var FTIS = getRisk(TIS);
  var FBIS = getRisk(BIS);

  $(".LS").text(LS + " " + FLS);
  $(".TIS").text(TIS + " " + FTIS);
  $(".BIS").text(BIS + " " + FBIS);

  score = "(";
  score = score + "SL:" + $("#sl").val() + "/";
  score = score + "M:" + $("#m").val() + "/";
  score = score + "O:" + $("#o").val() + "/";
  score = score + "S:" + $("#s").val() + "/";
  score = score + "ED:" + $("#ed").val() + "/";
  score = score + "EE:" + $("#ee").val() + "/";
  score = score + "A:" + $("#a").val() + "/";
  score = score + "ID:" + $("#id").val() + "/";
  score = score + "LC:" + $("#lc").val() + "/";
  score = score + "LI:" + $("#li").val() + "/";
  score = score + "LAV:" + $("#lav").val() + "/";
  score = score + "LAC:" + $("#lac").val() + "/";
  score = score + "FD:" + $("#fd").val() + "/";
  score = score + "RD:" + $("#rd").val() + "/";
  score = score + "NC:" + $("#nc").val() + "/";
  score = score + "PV:" + $("#pv").val();
  score = score + ")";
  $("#score").text(score);
  $("#score").attr(
    "href",
    "https://owasp.hacktivesecurity.com/?vector=" + score
  );

  if (FLS == "LOW") {
    $(".LS").addClass("classLow");
  } else if (FLS == "MEDIUM") {
    $(".LS").addClass("classMedium");
  } else {
    $(".LS").addClass("classHigh");
  }

  if (FTIS == "LOW") {
    $(".TIS").addClass("classLow");
  } else if (FTIS == "MEDIUM") {
    $(".TIS").addClass("classMedium");
  } else {
    $(".TIS").addClass("classHigh");
  }

  if (FBIS == "LOW") {
    $(".BIS").addClass("classLow");
  } else if (FBIS == "MEDIUM") {
    $(".BIS").addClass("classMedium");
  } else {
    $(".BIS").addClass("classHigh");
  }

  //FINAL
  var RS = getCriticaly(FLS, TIS > BIS ? FTIS : FBIS);
  console.log(RS);
  if (RS == "LOW") {
    $(".RS").text(RS);
    $(".RS").addClass("classLow");
  } else if (RS == "MEDIUM") {
    $(".RS").text(RS);
    $(".RS").addClass("classMedium");
  } else if (RS == "HIGH") {
    $(".RS").text(RS);
    $(".RS").addClass("classHigh");
  } else if (RS == "CRITICAL") {
    $(".RS").text(RS);
    $(".RS").addClass("classCritical");
  } else {
    $(".RS").text(RS);
    $(".RS").addClass("classNote");
  }

  updateRiskChart(dataset, RS);
}

function getRisk(score) {
  if (score == 0) return "INFO";
  if (score < 3) return "LOW";
  if (score < 6) return "MEDIUM";
  if (score <= 9) return "HIGH";
}

// Calculate final Risk Serverity
function getCriticaly(L, I) {
  //INFO
  if (L == "LOW" && I == "LOW") return "INFO";

  //LOW
  if (L == "LOW" && I == "MEDIUM") return "LOW";
  if (L == "MEDIUM" && I == "LOW") return "LOW";

  //MEDIUM
  if (L == "LOW" && I == "HIGH") return "MEDIUM";
  if (L == "MEDIUM" && I == "MEDIUM") return "MEDIUM";
  if (L == "HIGH" && I == "LOW") return "MEDIUM";

  //HIGH
  if (L == "HIGH" && I == "MEDIUM") return "HIGH";
  if (L == "MEDIUM" && I == "HIGH") return "HIGH";

  //CRITICAL
  if (L == "HIGH" && I == "HIGH") return "CRITICAL";
}

// Delete class before of calculate
function deleteClass() {
  // Delete Class Likelihood Score
  $(".LS").removeClass("classLow");
  $(".LS").removeClass("classMedium");
  $(".LS").removeClass("classHigh");

  // Delete Class Impact Score
  $(".TIS").removeClass("classLow");
  $(".TIS").removeClass("classMedium");
  $(".TIS").removeClass("classHigh");

  $(".BIS").removeClass("classLow");
  $(".BIS").removeClass("classMedium");
  $(".BIS").removeClass("classHigh");

  // Delete Class Risk Severity
  $(".RS").removeClass("classNote");
  $(".RS").removeClass("classLow");
  $(".RS").removeClass("classMedium");
  $(".RS").removeClass("classHigh");
  $(".RS").removeClass("classCritical");
}

function getUrlParameter(name) {
  name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
  var regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
  var results = regex.exec(location.search);
  return results === null
    ? ""
    : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function updateRiskChart(dataset, RS) {
  var c = 0;
  var dataset = dataset;

  switch (RS) {
    case "LOW":
      c = 3;
      break;
    case "MEDIUM":
      c = 2;
      break;
    case "HIGH":
      c = 1;
      break;
    case "CRITICAL":
      c = 0;
      break;
    default:
      c = 4;
      break;
  }

  riskChart.data.labels = threats;
  riskChart.data.datasets[0].data = dataset;
  riskChart.data.datasets[0].pointBackgroundColor = colors[c];
  riskChart.data.datasets[0].backgroundColor = backgrounds[c];
  riskChart.data.datasets[0].borderColor = colors[c];

  riskChart.update();
}
