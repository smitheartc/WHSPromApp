var ticketArray = [];

function logAllTickets() {
  ticketArray = [];
  firebase.firestore().collection("students")
  .get()
  .then(function(querySnapshot) {
    querySnapshot.forEach(function(doc) {
      console.log(doc.id, " => ", doc.data());
      if (ticketArray[doc.data().ticketNumber]) {
        ticketArray[doc.data().ticketNumber] += 1;
      } else {
        ticketArray[doc.data().ticketNumber] = 1;
      }
    })
  })
  .catch(function(error) {
    if (error.code == "permission-denied") {
      alert("Permission denied!\nYou must have authorization to use this app. If you believe this is a mistake, please contact Mrs. Patel.");
    } else {
      alert("Error getting documents: " + error);
    }
    console.log("Error getting documents: ", error);
  });
}

function checkAllTickets(start = 1, maximum = 1000) {
  for (i = start; i < 10000; i++) {
    if (ticketArray[i] == 1) {
      console.log("Ticket #" + i + " exists only once.")
    } else if (ticketArray[i] > 1) {
      console.error("Duplicate Ticket: " + ticketArray[i] + " instances of ticket #" + i);
      alert("Duplicate Ticket: " + ticketArray[i] + " instances of ticket #" + i);
    } else {
      console.error("Missing Ticket: ticket #" + i);
      if (i < maximum) {
        alert("Missing Ticket: ticket #" + i);
      }
    }
  }
}

function logAllPhotos(start = 1, maximum = 1000) {
  for (i = start; i <= maximum; i++) {
    var ticketInteger = i;
    var ticketString = leadingZeros(i);
    logIndividualPhoto(ticketInteger, ticketString);
  }
}

function logIndividualPhoto(ticketNumberInteger, ticketNumberString) {
  storageRef.child(ticketNumberString + ".jpg").getDownloadURL().then(function(url) {
    console.log("Successfully retrieved photo #" + ticketNumberString + " at url: " + url);
  }).catch(function(error) {
    storageRef.child(ticketNumberInteger + ".jpg").getDownloadURL().then(function(url) {
      console.error("Photo #" + ticketNumberString + " is missing leading zeros, but it can be found at url: " + url);
    }).catch(function(error) {
      console.error("Error retrieving photo #" + ticketNumberString + ": " + error);
      alert("Error retrieving photo #" + ticketNumberString + ": " + error);
    });
  });
}
