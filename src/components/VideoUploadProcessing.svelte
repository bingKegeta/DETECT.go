<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { FaceMesh, type Results } from "@mediapipe/face_mesh";
  import { drawLandmarks } from "@mediapipe/drawing_utils";
  import { writable } from "svelte/store";
  import { createSession } from "../scripts/session";

  import {
    LEFT_IRIS_CENTER,
    RIGHT_IRIS_CENTER,
    LEFT_EYE_CORNER,
    RIGHT_EYE_CORNER,
    NOSE_TIP,
    getNormalizedIrisPosition,
    getLandmarks,
  } from "../scripts/utils";
  import {
    calculateAffineTransformation,
    applyAffineTransformation
  } from "../scripts/affineTransformation";

  import type { Coordinates } from "../scripts/affineTransformation";
  import { applySmoothing } from "../scripts/smoothing";
  import { WebSocketConnection } from "../scripts/websocket";
  // import { number } from "astro:schema";
  // import { ProbabilityGraph } from "../scripts/graph";  // Import the ProbabilityGraph class

  // UI state variables
  let isPlaying = false;
  let videoLoaded = false;
  let isProcessing = false;
  let isLoadingFile = false;

  // Offscreen processing variables
  let videoElement: HTMLVideoElement;
  let processingCanvas: HTMLCanvasElement;
  let offscreenCtx: CanvasRenderingContext2D | null;
  let faceMesh: FaceMesh;
  let animationFrameId: number;

  const canvasWidth = 640;
  const canvasHeight = 480;

  const WEBSOCKET_URL = "ws://localhost:9090/ws";

  let variance: number | null = null;
  let acceleration: number | null = null;
  let probability: number | null = null;

  let ws: WebSocketConnection | null = null;
  // let probabilityGraph: ProbabilityGraph;  // Declare a ProbabilityGraph instance

  let isModalVisible = writable(false);
  let sessionName = "";
  let sessionCreated = false;
  let startTime = new Date().toISOString();
  let initialNoseTip: Coordinates | null = null; // Track the initial nose tip position

  let previousXValues: number[] = [];
  let previousYValues: number[] = [];

  let remainingTime = 0;
  let countdownTimer: number;


  function handleWebSocketMessage(data: any) {
    if (data.variance !== undefined && data.acceleration !== undefined && data.probability !== undefined) {
      probability = data.probability;
      console.log("Probability:", probability);

      // Update the probability graph with the new probability value
      // if (probability !== null) {
      //   probabilityGraph.updateProbability(probability);
      // }
    }
  }

  function startWebSocket() {
    if (ws) ws.close(); // Ensure no duplicate connections

    ws = new WebSocketConnection(WEBSOCKET_URL, handleWebSocketMessage);
    ws.start();
  }

  function processFrame() {
    if (faceMesh && videoElement) {
      faceMesh.send({ image: videoElement });
    }
  }


  // Start the countdown when video metadata is available
  function startCountdown() {
    clearInterval(countdownTimer);
    remainingTime = videoElement.duration;
    countdownTimer = setInterval(() => {
      remainingTime = Math.max(remainingTime - 1, 0);
      if (remainingTime === 0) {
        clearInterval(countdownTimer);
      }
    }, 1000);
  }

  function stopCountdown() {
    clearInterval(countdownTimer);
  }


  onMount(() => {
    // Initialize the probability graph
    // const graphCanvas = document.createElement("canvas");
    // graphCanvas.width = canvasWidth;
    // graphCanvas.height = 200; // Set a fixed height for the graph
    // document.body.appendChild(graphCanvas);
    // probabilityGraph = new ProbabilityGraph(graphCanvas);

    // Create a hidden video element for loading and playback
    videoElement = document.createElement("video");
    videoElement.style.display = "none";
    // Ensure inline playback (especially for mobile)
    videoElement.setAttribute("playsinline", "true");
    document.body.appendChild(videoElement);

  // === IMPORTANT ===
  // This "ended" event closes the modal automatically when the video finishes playing.
// Instead of automatically ending the session when the video ends,
// show the modal so the user can input the session name.
videoElement.onended = () => {
  isModalVisible.set(true);
};

    // Create a hidden canvas element for processing
    processingCanvas = document.createElement("canvas");
    processingCanvas.width = canvasWidth;
    processingCanvas.height = canvasHeight;
    processingCanvas.style.display = "none";
    document.body.appendChild(processingCanvas);
    offscreenCtx = processingCanvas.getContext("2d");

    // Initialize MediaPipe FaceMesh
    faceMesh = new FaceMesh({
      locateFile: (file) =>
        `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh/${file}`,
    });
    faceMesh.setOptions({
      maxNumFaces: 1,
      refineLandmarks: true,
      minDetectionConfidence: 0.43,
      minTrackingConfidence: 0.5,
    });

    if (!offscreenCtx) return;

    // Process results – drawing to the offscreen canvas (not displayed)
    // Inside the onResults function, after drawing landmarks:
    faceMesh.onResults((results: Results) => {
      if (offscreenCtx) {
        offscreenCtx.save();
        offscreenCtx.clearRect(0, 0, processingCanvas.width, processingCanvas.height);
        offscreenCtx.drawImage(
          results.image,
          0,
          0,
          processingCanvas.width,
          processingCanvas.height
        );
      }

      if (results.multiFaceLandmarks) {
        for (const landmarks of results.multiFaceLandmarks) {
          const irisCenters = getLandmarks(landmarks, [
            LEFT_IRIS_CENTER,
            RIGHT_IRIS_CENTER,
          ]);
          if (offscreenCtx) {
            drawLandmarks(offscreenCtx, irisCenters, {
              color: "#FF0000",
              lineWidth: 2,
            });

            const eyeCorners = getLandmarks(landmarks, [
              LEFT_EYE_CORNER,
              RIGHT_EYE_CORNER,
            ]);
            drawLandmarks(offscreenCtx, eyeCorners, {
              color: "#FF0000",
              lineWidth: 1,
            });

            const noseTip = getLandmarks(landmarks, [NOSE_TIP]);
            drawLandmarks(offscreenCtx, noseTip, {
              color: "#FF0000",
              lineWidth: 1,
            });
          }

          // Smoothing iris positions
          const { normX, normY, timestamp } = getNormalizedIrisPosition(
            landmarks,
            processingCanvas.width,
            processingCanvas.height
          );

          // Apply smoothing to the iris position
          const smoothedNormX = applySmoothing(normX, previousXValues);
          const smoothedNormY = applySmoothing(normY, previousYValues);

          // Track the current nose tip for affine transformation
          const currentNoseTip: Coordinates = getLandmarks(landmarks, [NOSE_TIP])[0];

          if (initialNoseTip) {
            // Calculate the affine transformation matrix based on initial and current nose tip positions
            const transformationMatrix = calculateAffineTransformation(initialNoseTip, currentNoseTip);

            // Apply the transformation to all landmarks (using smoothed iris position)
            const transformedLandmarks = landmarks.map(landmark => 
              applyAffineTransformation(landmark, transformationMatrix)
            );

            // Draw the transformed landmarks on the canvas
            if (offscreenCtx) {
              drawLandmarks(offscreenCtx, transformedLandmarks, {
                color: "#0000FF",
                lineWidth: 2,
              });
            }
          }

          const timestampInSeconds = timestamp / 1000; // Convert timestamp to seconds

          const metrics = {
            x: smoothedNormX,
            y: smoothedNormY,
            time: timestampInSeconds,
          };

          if (ws) {
            ws.sendMessage(metrics);
            console.log("WebSocket Sent:", metrics);
          }
        }
      }
      if (offscreenCtx) {
        offscreenCtx.restore();
      }
    });

    // === Pre-warm mediapipe: perform a dummy send on a blank frame ===
    if (offscreenCtx) {
      // Draw a blank frame (or any minimal dummy content)
      offscreenCtx.fillStyle = "#000";
      offscreenCtx.fillRect(0, 0, canvasWidth, canvasHeight);
      // Send the blank frame. This call will download and compile WASM, create a WebGL context, etc.
      faceMesh
        .send({ image: processingCanvas })
        .catch((error) => console.error("Error during warm-up:", error));
    }

    // Start WebSocket connection
    startWebSocket();
  });

  onDestroy(() => {
    if (videoElement) {
      videoElement.pause();
      videoElement.src = "";
      videoElement.remove();
    }
    if (animationFrameId) {
      cancelAnimationFrame(animationFrameId);
    }
    if (ws) {
      ws.close();
    }
  });

  // Process the video frame by frame:
  async function processVideoFrame() {
    // Check immediately: if paused or ended, stop processing.
    if (videoElement.paused || videoElement.ended) {
      isProcessing = false;
      return;
    }
    if (offscreenCtx) {
      offscreenCtx.drawImage(videoElement, 0, 0, canvasWidth, canvasHeight);
    }
    // Check again before processing the frame.
    if (videoElement.paused || videoElement.ended) {
      isProcessing = false;
      return;
    }
    try {
      await faceMesh.send({ image: processingCanvas });
    } catch (error) {
      console.error("Error processing frame:", error);
    }
    // If video got paused while processing, stop here.
    if (videoElement.paused || videoElement.ended) {
      isProcessing = false;
      return;
    }
    animationFrameId = requestAnimationFrame(processVideoFrame);
  }

  // Triggered when a file is selected.
  function handleVideoUpload(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files ? input.files[0] : null;
  if (file) {
    const url = URL.createObjectURL(file);
    videoElement.src = url;
    // Start countdown once metadata is available (duration etc.)
    videoElement.onloadedmetadata = () => {
      startCountdown();
    };
    videoElement.onloadeddata = () => {
      // Close the modal automatically when the video is done uploading
      isModalVisible.set(false);
      videoLoaded = true;
      isPlaying = true;
      isProcessing = true;
      videoElement.play();
      processVideoFrame();
    };
  }
}

  // Control handlers
  function handlePlay() {
    if (videoLoaded && videoElement.paused) {
      isPlaying = true;
      isProcessing = true;
      videoElement.play();
      processVideoFrame();
    }
  }

  function handlePause() {
    if (videoLoaded && !videoElement.paused) {
      isPlaying = false;
      // Immediately stop processing and cancel the next frame.
      isProcessing = false;
      videoElement.pause();
      cancelAnimationFrame(animationFrameId);
    }
  }

  function handleStop() {
  if (!sessionCreated) {
    isModalVisible.set(true);
  } else {
    endSession();
  }
}

function endSession() {
  if (!sessionCreated) {
    const sessionData = {
      name: sessionName || "Session", // Default name if none provided
      start_time: startTime,
      end_time: new Date().toISOString(),
      var_min: variance ?? 0,
      var_max: variance ?? 0,
      acc_min: acceleration ?? 0,
      acc_max: acceleration ?? 0
    };

    createSession(sessionData);
    sessionCreated = false; 
    isModalVisible.set(false);
  }
  if (videoLoaded) {
    isPlaying = false;
    videoLoaded = false;
    videoElement.pause();
    videoElement.currentTime = 0;
    if (offscreenCtx) {
      offscreenCtx.clearRect(0, 0, canvasWidth, canvasHeight);
    }
  }
  window.location.href = "/dashboard";
}

</script>

<!--
  1) Loading Spinner for when the file is being selected and loaded
     If you want it in a different place, move this {#if isLoadingFile} block
-->
{#if isLoadingFile}
  <div class="spinner mt-4 flex justify-center">
    <div class="loader"></div>
  </div>
{/if}

{#if videoLoaded && isPlaying}
  <div class="mt-2 text-center">
    Estimated Time Remaining: {Math.floor(remainingTime)} sec
  </div>
{/if}

<div class="flex flex-col items-center justify-center rounded-lg border-4 border-primary opacity-90 shadow-glow bg-base-200 m-4 p-4">
  <!-- Processing indicator: Spinner while processing, Pause symbol when paused -->
  {#if isProcessing}
    <div class="spinner mt-4 flex justify-center">
      <div class="loader"></div>
    </div>
  {:else if videoLoaded && !isPlaying}
    <div class="pause-icon mt-4 flex justify-center">
      <div class="pause-symbol">&#10074;&#10074;</div>
    </div>
  {/if}

  <!-- Visible file input with original styling -->
  <input
    type="file"
    accept="video/*"
    on:change={handleVideoUpload}
    id="fileInput"
    class="flex p-2 bg-secondary hover:text-secondary-content rounded-md w-fit my-2 shadow-glow hover:scale-105 transition-transform"
    disabled={isLoadingFile}
  />

  {#if videoLoaded}
    <div class="flex w-full font-semibold">
      <!-- Example: your Play, Pause, Stop buttons -->
      <!--
      <button on:click={handlePlay}>Play</button>
      <button on:click={handlePause}>Pause</button>
      <button on:click={handleStop}>Stop</button>
      -->
    </div>
  {/if}

  <!-- Session Name Modal -->
<!-- Session Name Modal -->
{#if $isModalVisible}
  <div class="fixed inset-0 bg-base-200 bg-opacity-75 flex justify-center items-center z-10">
    <div class="bg-base-100 p-6 rounded-lg border-4 border-primary shadow-xl w-96">
      
      <!-- High-Contrast Heading -->
      <h2 class="font-extrabold text-3xl text-secondary mb-4 text-center uppercase tracking-wide">
        Enter Session Name
      </h2>
      
      <!-- Input Field -->
      <input
        type="text"
        bind:value={sessionName}
        class="border border-primary p-3 rounded-md w-full mb-4
               bg-base-200 text-primary-content focus:ring-4 focus:ring-primary
               transition-all outline-none"
        placeholder="Session Name"
      />
      
       <!-- Buttons Section -->
       <div class="flex justify-between">
        <button
          on:click={() => isModalVisible.set(false)}
          class="bg-neutral text-primary-content p-3 rounded-md hover:bg-error
                 transition-all font-semibold w-1/2 mr-2"
        >
          Cancel
        </button>
        <button
          on:click={endSession}
          class="bg-neutral text-primary-content p-3 rounded-md hover:bg-success
                 transition-all font-semibold w-1/2"
        >
          Submit
        </button>
      </div>

    </div>
  </div>
{/if}

</div>

<style>
  /* Basic spinner styling */
  .spinner {
    margin: 1rem auto;
  }
  .loader {
    border: 8px solid rgba(0, 0, 0, 0.1);
    border-top: 8px solid #3498db; /* or your color choice */
    border-radius: 50%;
    width: 48px;
    height: 48px;
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  /* Optional pause symbol styling */
  .pause-symbol {
    font-size: 2rem;
    color: #fff;
  }
</style>
