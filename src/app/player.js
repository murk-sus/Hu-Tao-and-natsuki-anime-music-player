const tracks = [
  {
    title: "Night Sakura Drift",
    artist: "Luna Echo",
    src: "https://cdn.pixabay.com/download/audio/2022/03/15/audio_4ef412f523.mp3?filename=lofi-study-112191.mp3"
  },
  {
    title: "Crimson Lanterns",
    artist: "Kitsune Drive",
    src: "https://cdn.pixabay.com/download/audio/2022/08/02/audio_88447aa61d.mp3?filename=beauty-flow-117905.mp3"
  },
  {
    title: "Paper Hearts",
    artist: "Skyline Senpai",
    src: "https://cdn.pixabay.com/download/audio/2022/05/16/audio_02f6f16168.mp3?filename=japanese-city-pop-111212.mp3"
  }
];

const audio = document.getElementById("audio");
const playBtn = document.getElementById("play");
const prevBtn = document.getElementById("prev");
const nextBtn = document.getElementById("next");
const seek = document.getElementById("seek");
const currentTimeEl = document.getElementById("current-time");
const durationEl = document.getElementById("duration");
const trackTitle = document.getElementById("track-title");
const trackArtist = document.getElementById("track-artist");
const playlistEl = document.getElementById("playlist");

let currentIndex = 0;

const formatTime = (seconds) => {
  if (!Number.isFinite(seconds)) return "0:00";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
};

const renderPlaylist = () => {
  playlistEl.innerHTML = "";
  tracks.forEach((track, idx) => {
    const li = document.createElement("li");
    li.textContent = `${track.title} — ${track.artist}`;
    li.classList.toggle("active", idx === currentIndex);
    li.addEventListener("click", () => {
      loadTrack(idx);
      audio.play();
    });
    playlistEl.appendChild(li);
  });
};

const loadTrack = (idx) => {
  currentIndex = (idx + tracks.length) % tracks.length;
  const track = tracks[currentIndex];
  audio.src = track.src;
  trackTitle.textContent = track.title;
  trackArtist.textContent = track.artist;
  playBtn.textContent = "⏸";
  renderPlaylist();
};

playBtn.addEventListener("click", () => {
  if (audio.paused) {
    audio.play();
  } else {
    audio.pause();
  }
});

audio.addEventListener("play", () => {
  playBtn.textContent = "⏸";
});

audio.addEventListener("pause", () => {
  playBtn.textContent = "▶";
});

prevBtn.addEventListener("click", () => {
  loadTrack(currentIndex - 1);
  audio.play();
});

nextBtn.addEventListener("click", () => {
  loadTrack(currentIndex + 1);
  audio.play();
});

audio.addEventListener("timeupdate", () => {
  currentTimeEl.textContent = formatTime(audio.currentTime);
  seek.value = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
});

audio.addEventListener("loadedmetadata", () => {
  durationEl.textContent = formatTime(audio.duration);
});

seek.addEventListener("input", () => {
  if (audio.duration) {
    audio.currentTime = (seek.value / 100) * audio.duration;
  }
});

audio.addEventListener("ended", () => {
  loadTrack(currentIndex + 1);
  audio.play();
});

loadTrack(0);
