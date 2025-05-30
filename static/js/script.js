function navigate(section) {
    // For now, just log the navigation
    console.log('Navigating to:', section);
    // This will be implemented with actual navigation logic later
}

// Initialize IndexedDB
let db;
let dbInitialized = false;

// Function to initialize IndexedDB
function initializeDB() {
    return new Promise((resolve, reject) => {
        const dbRequest = indexedDB.open('keyStore', 1);

        dbRequest.onerror = (event) => {
            console.error('IndexedDB error:', event.target.error);
            reject(event.target.error);
        };

        dbRequest.onupgradeneeded = (event) => {
            db = event.target.result;
            if (!db.objectStoreNames.contains('keys')) {
                db.createObjectStore('keys', { keyPath: 'username' });
            }
        };

        dbRequest.onsuccess = (event) => {
            db = event.target.result;
            dbInitialized = true;
            resolve();
        };
    });
}

// Function to store private key in IndexedDB
async function storePrivateKey(username, privateKey) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['keys'], 'readwrite');
        const store = transaction.objectStore('keys');
        const request = store.put({ username, privateKey });
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

// Function to encrypt a message
async function encryptMessage(message, recipientUsername) {
    try {
        // Get recipient's public key
        const response = await fetch(`/api/keys/${recipientUsername}`);
        if (!response.ok) {
            throw new Error('Failed to fetch recipient public key');
        }
        const { public_key } = await response.json();

        // Import recipient's public key
        const publicKey = await window.crypto.subtle.importKey(
            "spki",
            Uint8Array.from(atob(public_key), c => c.charCodeAt(0)),
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );

        // Encrypt the message
        const encodedMessage = new TextEncoder().encode(message);
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            encodedMessage
        );

        // Convert to base64 for transmission
        return btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

// Function to decrypt a message
async function decryptMessage(encryptedMessage, username) {
    try {
        console.log('Starting decryption for user:', username);
        
        // Get private key from IndexedDB
        const transaction = db.transaction(['keys'], 'readonly');
        const store = transaction.objectStore('keys');
        const request = store.get(username);

        const privateKeyData = await new Promise((resolve, reject) => {
            request.onsuccess = () => {
                console.log('Found key in IndexedDB:', !!request.result);
                resolve(request.result?.privateKey);
            };
            request.onerror = () => reject(request.error);
        });

        if (!privateKeyData) {
            throw new Error('Private key not found for user: ' + username);
        }

        // Import private key
        console.log('Importing private key...');
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            new Uint8Array(privateKeyData),
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt"]
        );
        console.log('Private key imported successfully');

        // Convert base64 to array buffer
        console.log('Decoding base64 message:', encryptedMessage);
        const messageArray = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
        
        // Decrypt the message
        console.log('Decrypting message...');
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            messageArray
        );
        console.log('Message decrypted successfully');

        const decryptedText = new TextDecoder().decode(decryptedData);
        console.log('Decrypted text:', decryptedText);
        return decryptedText;
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}

// Function to generate key pair and store keys
async function generateAndStoreKeys(username) {
    try {
        console.log('Starting key generation for user:', username);
        
        // Generate key pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        console.log('Key pair generated successfully');

        // Export public key
        const publicKey = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );
        console.log('Public key exported successfully');
        
        // Export private key
        const privateKey = await window.crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey
        );
        console.log('Private key exported successfully');

        // Store private key in IndexedDB
        console.log('Storing private key in IndexedDB...');
        await storePrivateKey(username, Array.from(new Uint8Array(privateKey)));
        console.log('Private key stored in IndexedDB');

        // Send public key to server
        console.log('Sending public key to server...');
        const response = await fetch('/api/keys/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey)))
            })
        });

        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        console.log('Public key registered with server successfully');

        return true;
    } catch (error) {
        console.error('Key generation error:', error);
        console.error('Error stack:', error.stack);
        return false;
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    // Initialize IndexedDB first
    try {
        await initializeDB();
        console.log('IndexedDB initialized successfully');
    } catch (error) {
        console.error('Failed to initialize IndexedDB:', error);
        return;
    }

    const socket = io();
    // Get current user from session or set to Guest if not logged in
    const currentUser = document.body.getAttribute('data-current-user') || 'Guest';

    // Generate keys for logged-in users
    if (currentUser !== 'Guest' && dbInitialized) {
        try {
            const transaction = db.transaction(['keys'], 'readonly');
            const store = transaction.objectStore('keys');
            const request = store.get(currentUser);

            request.onsuccess = async (event) => {
                if (!event.target.result) {
                    // No keys found, generate new ones
                    console.log('Generating new keys for user:', currentUser);
                    await generateAndStoreKeys(currentUser);
                }
            };

            request.onerror = (event) => {
                console.error('Error checking for existing keys:', event.target.error);
            };
        } catch (error) {
            console.error('Error during key generation check:', error);
        }
    }
    const activeChats = new Map(); // Store active chat windows

    // Initialize Your Tasks section, progress bar, and leaderboard
    updateYourTasks();
    updateProgressBar();
    updateLeaderboard();

    // Video call functionality
    let localStream = null;
    const localVideo = document.getElementById('localVideo');
    const startCallBtn = document.querySelector('.start-call-btn');
    const micBtn = document.querySelector('.mic-btn');
    const cameraBtn = document.querySelector('.camera-btn');
    const screenBtn = document.querySelector('.screen-btn');
    const leaveBtn = document.querySelector('.leave-btn');

    // Start call button click handler
    startCallBtn?.addEventListener('click', async () => {
        try {
            localStream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });
            localVideo.srcObject = localStream;
            startCallBtn.style.display = 'none';
            document.querySelector('.controls').style.display = 'flex';
        } catch (err) {
            console.error('Error accessing media devices:', err);
            alert('Could not access camera or microphone');
        }
    });

    // Mute/unmute microphone
    micBtn?.addEventListener('click', () => {
        if (localStream) {
            const audioTrack = localStream.getAudioTracks()[0];
            audioTrack.enabled = !audioTrack.enabled;
            micBtn.querySelector('i').textContent = audioTrack.enabled ? '🎤' : '🔇';
            micBtn.style.backgroundColor = audioTrack.enabled ? 'rgba(255,255,255,0.2)' : '#dc3545';
        }
    });

    // Toggle camera
    cameraBtn?.addEventListener('click', () => {
        if (localStream) {
            const videoTrack = localStream.getVideoTracks()[0];
            videoTrack.enabled = !videoTrack.enabled;
            cameraBtn.querySelector('i').textContent = videoTrack.enabled ? '📹' : '🚫';
            cameraBtn.style.backgroundColor = videoTrack.enabled ? 'rgba(255,255,255,0.2)' : '#dc3545';
        }
    });

    // Share screen
    screenBtn?.addEventListener('click', async () => {
        try {
            const screenStream = await navigator.mediaDevices.getDisplayMedia({
                video: true
            });
            const videoTrack = screenStream.getVideoTracks()[0];
            const sender = localStream.getVideoTracks()[0];
            
            // Replace camera with screen share
            if (sender) {
                localVideo.srcObject = screenStream;
                screenBtn.style.backgroundColor = '#28a745';
                screenBtn.querySelector('i').textContent = '🔄';

                // When screen sharing stops
                videoTrack.onended = async () => {
                    try {
                        const newStream = await navigator.mediaDevices.getUserMedia({ video: true });
                        localVideo.srcObject = newStream;
                        screenBtn.style.backgroundColor = 'rgba(255,255,255,0.2)';
                        screenBtn.querySelector('i').textContent = '💻';
                    } catch (err) {
                        console.error('Error reverting to camera:', err);
                    }
                };
            }
        } catch (err) {
            console.error('Error sharing screen:', err);
            alert('Could not share screen');
        }
    });

    // Leave call
    leaveBtn?.addEventListener('click', () => {
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
            localVideo.srcObject = null;
            startCallBtn.style.display = 'block';
            document.querySelector('.controls').style.display = 'none';
        }
    });

    // Hide controls initially
    document.querySelector('.controls')?.style.setProperty('display', 'none');

    // Announcement editing functionality
    const announcements = document.querySelectorAll('.announcement');
    
    // Keep announcements in sync across all pages
    function updateAllAnnouncements(text) {
        announcements.forEach(announcement => {
            announcement.textContent = text;
        });
    }

    announcements.forEach(announcement => {
        // Handle double-click to edit
        announcement.addEventListener('dblclick', () => {
            announcement.setAttribute('contenteditable', 'true');
            announcement.focus();
        });

        // Handle Enter key to save
        announcement.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                announcement.setAttribute('contenteditable', 'false');
                updateAllAnnouncements(announcement.textContent);
            }
        });

        // Handle focus out to save
        announcement.addEventListener('blur', () => {
            announcement.setAttribute('contenteditable', 'false');
            updateAllAnnouncements(announcement.textContent);
        });
    });

    // Tab Navigation
    const navButtons = document.querySelectorAll('.nav-button');
    const pages = document.querySelectorAll('.page');

    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetPage = button.getAttribute('data-page');
            
            // Update active states
            navButtons.forEach(btn => btn.classList.remove('active'));
            pages.forEach(page => page.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(targetPage).classList.add('active');
        });
    });

    // Pinned Messages Feature
    const pinnedDialog = document.getElementById('pinned-dialog');
    const pinnedMessagesList = pinnedDialog.querySelector('.pinned-messages-list');
    const pinnedMessagesBtn = document.querySelector('.pinned-messages-btn');
    const messageMenu = document.getElementById('message-menu');
    let pinnedMessages = new Map(); // Store pinned messages
    let selectedMessage = null;

    // Show pinned messages dialog
    pinnedMessagesBtn.addEventListener('click', () => {
        pinnedDialog.style.display = 'block';
        
        // Create and show overlay
        const overlay = document.createElement('div');
        overlay.className = 'overlay';
        document.body.appendChild(overlay);
        overlay.style.display = 'block';
    });

    // Close pinned messages dialog
    document.querySelector('.close-pinned').addEventListener('click', closePinnedDialog);

    function closePinnedDialog() {
        pinnedDialog.style.display = 'none';
        document.querySelector('.overlay')?.remove();
    }

    // Show context menu for messages
    document.querySelector('.messages').addEventListener('contextmenu', (e) => {
        e.preventDefault();
        const messageElement = e.target.closest('.message');
        if (!messageElement) return;

        selectedMessage = messageElement;
        
        // Position and show context menu
        messageMenu.style.display = 'block';
        messageMenu.style.left = e.pageX + 'px';
        messageMenu.style.top = e.pageY + 'px';
    });

    // Hide context menus when clicking elsewhere
    document.addEventListener('click', () => {
        messageMenu.style.display = 'none';
    });

    // Pin message from context menu
    document.querySelector('.pin-message-btn').addEventListener('click', () => {
        if (!selectedMessage) return;

        const messageId = selectedMessage.dataset.messageId || Date.now().toString();
        if (!selectedMessage.dataset.messageId) {
            selectedMessage.dataset.messageId = messageId;
        }

        if (!pinnedMessages.has(messageId)) {
            const messageContent = selectedMessage.innerHTML;
            pinnedMessages.set(messageId, messageContent);
            
            // Add to pinned messages list
            const pinnedMessage = document.createElement('div');
            pinnedMessage.className = 'pinned-message';
            pinnedMessage.innerHTML = `
                <div class="header">
                    <div class="user">${messageContent.split('</span>')[0]}</div>
                    <button class="unpin-btn" data-message-id="${messageId}">Unpin</button>
                </div>
                <div class="content">${messageContent.split('</span>')[1]}</div>
            `;
            pinnedMessagesList.appendChild(pinnedMessage);
            
            // Show brief confirmation
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.textContent = 'Message pinned!';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
        }

        // Hide context menu
        messageMenu.style.display = 'none';
    });

    // Unpin a message
    pinnedMessagesList.addEventListener('click', (e) => {
        if (e.target.matches('.unpin-btn')) {
            const messageId = e.target.dataset.messageId;
            pinnedMessages.delete(messageId);
            e.target.closest('.pinned-message').remove();
        }
    });

    // Message Input (Main Chat)
    const messageInput = document.querySelector('.message-input input');
    const sendButton = document.querySelector('.message-input button');

    function sendMessage() {
        const message = messageInput.value.trim();
        if (message) {
            // Emit the message via socket
            socket.emit('group_message', {
                sender: currentUser,
                message: message
            });
            
            // Clear input
            messageInput.value = '';
        }
    }

    sendButton.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // Task Manager
    const taskModal = document.getElementById('task-modal');
    const taskForm = document.getElementById('task-form');
    const addTaskBtn = document.querySelector('.add-task-btn');
    const closeModalBtns = document.querySelectorAll('.close-modal');
    const taskContextMenu = document.getElementById('task-context-menu');
    const taskGroups = document.querySelectorAll('.task-group');
    let currentTask = null;

    // Show task modal
    addTaskBtn?.addEventListener('click', () => {
        taskModal.style.display = 'block';
        taskForm.reset();
        // Set minimum date as today for due date
        const today = new Date().toISOString().split('T')[0];
        document.getElementById('task-due-date').min = today;
    });

    // Close task modal
    closeModalBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            taskModal.style.display = 'none';
        });
    });

    // Function to update Your Tasks section
    function updateYourTasks() {
        const yourTasksList = document.querySelector('.task-list-vertical');
        yourTasksList.innerHTML = ''; // Clear existing tasks
        
        // Get all tasks from task manager
        document.querySelectorAll('.task-group .tasks .task').forEach(task => {
            const assignee = task.dataset.assignee;
            if (assignee === currentUser) {
                const taskName = task.querySelector('label').textContent.split(' (Due:')[0];
                const isCompleted = task.classList.contains('completed');
                
                const taskElement = document.createElement('div');
                taskElement.className = `task${isCompleted ? ' completed' : ''}`;
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.id = 'personal-task-' + Date.now() + Math.random();
                checkbox.checked = isCompleted;
                
                const label = document.createElement('label');
                label.htmlFor = checkbox.id;
                label.textContent = taskName;
                
                taskElement.appendChild(checkbox);
                taskElement.appendChild(label);
                
                // Sync checkbox state with main task
                checkbox.addEventListener('change', () => {
                    task.querySelector('input[type="checkbox"]').click();
                });
                
                yourTasksList.appendChild(taskElement);
            }
        });
    }

    // Function to update progress bar
    function updateProgressBar() {
        const totalTasks = document.querySelectorAll('.task-group .tasks .task').length;
        const completedTasks = document.querySelectorAll('.task-group .tasks .task.completed').length;
        const progressPercentage = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;
        
        const progressBar = document.querySelector('.progress');
        progressBar.style.width = `${progressPercentage}%`;
        
        // Update leaderboard when tasks are updated
        updateLeaderboard();
    }

    // Function to update leaderboard based on completed tasks
    function updateLeaderboard() {
        const memberStats = new Map();
        const members = ['Alice', 'Bob', 'Charlie', 'Joanna'];

        // Initialize member stats
        members.forEach(member => {
            memberStats.set(member, {
                completed: 0,
                total: 0,
                points: 0
            });
        });

        // Count completed tasks and calculate points for each member
        document.querySelectorAll('.task-group .tasks .task').forEach(task => {
            const assignee = task.dataset.assignee;
            if (memberStats.has(assignee)) {
                const stats = memberStats.get(assignee);
                stats.total++;
                
                if (task.classList.contains('completed')) {
                    stats.completed++;
                    // Each completed task is worth points based on its value or default to 3
                    stats.points += parseInt(task.dataset.points || '3');
                }
            }
        });

        // Sort members by points
        const sortedMembers = Array.from(memberStats.entries())
            .sort((a, b) => b[1].points - a[1].points);

        // Update leaderboard UI
        const leaderboardList = document.querySelector('.leaderboard-list');
        leaderboardList.innerHTML = '';

        // Calculate total group points
        const totalGroupPoints = sortedMembers.reduce((sum, [_, stats]) => sum + stats.points, 0);
        document.querySelector('.total-points .points').textContent = totalGroupPoints;

        // Create member cards
        sortedMembers.forEach(([member, stats], index) => {
            const progressPercentage = stats.total > 0 ? (stats.completed / stats.total) * 100 : 0;
            const memberCard = document.createElement('div');
            memberCard.className = `member-card${index === 0 ? ' first-place' : ''}`;
            memberCard.innerHTML = `
                <div class="rank">${index + 1}</div>
                <div class="member-info">
                    <h3>${member}${member === 'Joanna' ? ' (You)' : ''}</h3>
                    <div class="points-info">
                        <span class="points">${stats.points} points</span>
                        <div class="points-bar">
                            <div class="progress" style="width: ${progressPercentage}%"></div>
                        </div>
                    </div>
                    <div class="tasks-completed">${stats.completed} tasks completed</div>
                </div>
            `;
            leaderboardList.appendChild(memberCard);
        });
    }

    // Variable to track if we're editing an existing task
    let editingTask = null;

    // Create/Edit task form handler
    taskForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const taskData = {
            name: document.getElementById('task-name').value,
            description: document.getElementById('task-description').value,
            points: document.getElementById('task-points').value,
            dueDate: document.getElementById('task-due-date').value,
            assignee: document.getElementById('task-assignee').value,
            status: 'todo'
        };

        if (editingTask) {
            // Update existing task
            const wasAssignedToCurrentUser = editingTask.dataset.assignee === currentUser;
            const willBeAssignedToCurrentUser = taskData.assignee === currentUser;

            // Update task element
            editingTask.dataset.points = taskData.points;
            editingTask.dataset.assignee = taskData.assignee;
            editingTask.dataset.description = taskData.description;
            editingTask.dataset.dueDate = taskData.dueDate;
            editingTask.querySelector('label').textContent = `${taskData.name} (Due: ${formatDate(taskData.dueDate)}) (${taskData.assignee})`;

            // Update UI if task assignment changed
            if (wasAssignedToCurrentUser || willBeAssignedToCurrentUser) {
                updateYourTasks();
            }
            editingTask = null;
            
            // Reset modal title and button text
            document.querySelector('#task-modal .modal-header h3').textContent = 'Create New Task';
            document.querySelector('#task-form .btn-primary').textContent = 'Create Task';
        } else {
            // Create new task element
            const taskElement = createTaskElement(taskData);
            document.querySelector('.task-group:first-child .tasks').appendChild(taskElement);
            
            // Update Your Tasks section if the task is assigned to current user
            if (taskData.assignee === currentUser) {
                updateYourTasks();
            }
        }
        
        // Update progress bar and leaderboard
        updateProgressBar();
        updateLeaderboard();
        
        // Close modal
        taskModal.style.display = 'none';
        taskForm.reset();
    });

    // Create task element
    function createTaskElement(taskData) {
        const task = document.createElement('div');
        task.className = 'task';
        task.draggable = true;
        task.dataset.points = taskData.points;
        task.dataset.assignee = taskData.assignee;
        task.dataset.description = taskData.description;
        task.dataset.dueDate = taskData.dueDate;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = 'task-' + Date.now();

        const label = document.createElement('label');
        label.htmlFor = checkbox.id;
        label.textContent = `${taskData.name} (Due: ${formatDate(taskData.dueDate)})`;

        // Add assignee info to the task
        const assigneeSpan = document.createElement('span');
        assigneeSpan.className = 'task-assignee';
        assigneeSpan.textContent = ` (${taskData.assignee})`;
        label.appendChild(assigneeSpan);

        task.appendChild(checkbox);
        task.appendChild(label);

        // Add drag and drop listeners
        task.addEventListener('dragstart', handleDragStart);
        task.addEventListener('dragend', handleDragEnd);

        // Add context menu
        task.addEventListener('contextmenu', showTaskContextMenu);

        // Add checkbox listener
        checkbox.addEventListener('change', () => {
            task.classList.toggle('completed', checkbox.checked);
            if (checkbox.checked) {
                // Move to Done column
                document.querySelector('.task-group:last-child .tasks').appendChild(task);
            }
            // Update Your Tasks section if the task belongs to current user
            if (task.dataset.assignee === currentUser) {
                updateYourTasks();
            }
            // Update progress bar
            updateProgressBar();
        });

        return task;
    }

    // Format date to be more readable
    function formatDate(dateString) {
        const options = { month: 'short', day: 'numeric' };
        return new Date(dateString).toLocaleDateString(undefined, options);
    }

    // Drag and Drop Handlers
    function handleDragStart(e) {
        this.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', '');
        currentTask = this;
    }

    function handleDragEnd() {
        this.classList.remove('dragging');
        document.querySelectorAll('.task-group').forEach(group => {
            group.classList.remove('drag-over');
        });
    }

    // Add drag and drop handlers to task groups
    taskGroups.forEach(group => {
        group.addEventListener('dragover', handleGroupDragOver);
        group.addEventListener('dragleave', handleGroupDragLeave);
        group.addEventListener('drop', handleGroupDrop);
    });

    function handleGroupDragOver(e) {
        e.preventDefault();
        this.classList.add('drag-over');
    }

    function handleGroupDragLeave(e) {
        if (e.target === this) {
            this.classList.remove('drag-over');
        }
    }

    function handleGroupDrop(e) {
        e.preventDefault();
        if (currentTask) {
            const tasksContainer = this.querySelector('.tasks');
            tasksContainer.appendChild(currentTask);
            this.classList.remove('drag-over');
        }
    }

    // Context Menu
    function showTaskContextMenu(e) {
        e.preventDefault();
        currentTask = this;
        
        // Position context menu
        taskContextMenu.style.display = 'block';
        taskContextMenu.style.left = e.pageX + 'px';
        taskContextMenu.style.top = e.pageY + 'px';
    }

    // Hide context menu when clicking elsewhere
    document.addEventListener('click', () => {
        taskContextMenu.style.display = 'none';
    });

    // Edit task
    document.querySelector('.edit-task-btn')?.addEventListener('click', () => {
        if (!currentTask) return;

        // Set editing mode
        editingTask = currentTask;

        // Fill form with current task data
        document.getElementById('task-name').value = currentTask.querySelector('label').textContent.split(' (Due:')[0];
        document.getElementById('task-description').value = currentTask.dataset.description;
        document.getElementById('task-points').value = currentTask.dataset.points;
        document.getElementById('task-due-date').value = currentTask.dataset.dueDate;
        document.getElementById('task-assignee').value = currentTask.dataset.assignee;

        // Update modal title and button text
        document.querySelector('#task-modal .modal-header h3').textContent = 'Edit Task';
        document.querySelector('#task-form .btn-primary').textContent = 'Save Changes';

        // Show modal
        taskModal.style.display = 'block';
        taskContextMenu.style.display = 'none';
    });

    // Delete task
    document.querySelector('.delete-task-btn')?.addEventListener('click', () => {
        if (!currentTask) return;
        
        // Check if task was assigned to current user before deleting
        const wasAssignedToCurrentUser = currentTask.dataset.assignee === currentUser;
        
        // Remove the task
        currentTask.remove();
        
        // Update UI
        if (wasAssignedToCurrentUser) {
            updateYourTasks();
        }
        updateProgressBar();
        updateLeaderboard();
        taskContextMenu.style.display = 'none';
    });

    // Function to show chicken congratulations
    function showChickenCongrats(taskName, assignee) {
        // Remove any existing congrats
        const existingCongrats = document.querySelector('.chicken-congrats');
        if (existingCongrats) {
            existingCongrats.remove();
        }

        // Get chicken position
        const chicken = document.querySelector('.duck-mascot img');
        const chickenRect = chicken.getBoundingClientRect();

        // Create new congrats message
        const congrats = document.createElement('div');
        congrats.className = 'chicken-congrats';
        congrats.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 5px;">🎉 Task Completed! 🎉</div>
            Great job ${assignee}!<br>
            You finished: "${taskName}"
        `;

        // Position next to chicken
        congrats.style.position = 'fixed';
        congrats.style.left = `${chickenRect.right + 20}px`;
        congrats.style.top = `${chickenRect.top - 10}px`;

        // Add to document
        document.body.appendChild(congrats);

        // Remove after 5 seconds
        setTimeout(() => {
            congrats.style.opacity = '0';
            congrats.style.transform = 'scale(0.8) translateY(20px)';
            setTimeout(() => congrats.remove(), 300);
        }, 4700);
    };

    // Function to handle task checkbox change
    function handleTaskCheckboxChange(checkbox) {
        const taskElement = checkbox.closest('.task');
        const taskText = checkbox.nextElementSibling;
        const taskName = taskText.textContent.split(' (Due:')[0];
        const assignee = taskElement.dataset.assignee;

        if (checkbox.checked) {
            taskText.style.textDecoration = 'line-through';
            taskText.style.color = '#888';
            if (assignee) {
                showChickenCongrats(taskName, assignee);
            }
        } else {
            taskText.style.textDecoration = 'none';
            taskText.style.color = 'inherit';
        }
    }

    // Bind checkbox events for both task manager and your tasks section
    function bindTaskCheckboxEvents() {
        const allTaskCheckboxes = document.querySelectorAll('.task input[type="checkbox"]');
        allTaskCheckboxes.forEach(checkbox => {
            // Remove existing listener to prevent duplicates
            checkbox.removeEventListener('change', () => handleTaskCheckboxChange(checkbox));
            // Add new listener
            checkbox.addEventListener('change', () => handleTaskCheckboxChange(checkbox));
        });
    }

    // Initial binding
    bindTaskCheckboxEvents();

    // Rebind events when tasks are updated
    const taskObserver = new MutationObserver(() => {
        bindTaskCheckboxEvents();
    });

    // Observe both task containers for changes
    const taskContainers = document.querySelectorAll('.tasks, .task-list-vertical');
    taskContainers.forEach(container => {
        taskObserver.observe(container, { childList: true, subtree: true });
    });

    // Report Feature
    const contextMenu = document.getElementById('report-menu');
    const reportDialog = document.getElementById('report-dialog');
    const reportedUserSpan = reportDialog.querySelector('.reported-user');
    let reportedUsername = '';

    // Handle right click on member
    document.querySelectorAll('.member').forEach(member => {
        member.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const username = member.getAttribute('data-username');
            
            // Don't show report menu for self
            if (username === currentUser) return;
            
            reportedUsername = username;
            
            // Position and show context menu
            contextMenu.style.display = 'block';
            contextMenu.style.left = e.pageX + 'px';
            contextMenu.style.top = e.pageY + 'px';
        });
    });

    // Hide context menu when clicking elsewhere
    document.addEventListener('click', () => {
        contextMenu.style.display = 'none';
    });

    // Handle report button click
    document.querySelector('.report-button').addEventListener('click', () => {
        contextMenu.style.display = 'none';
        reportedUserSpan.textContent = reportedUsername;
        reportDialog.style.display = 'block';
        
        // Create and show overlay
        const overlay = document.createElement('div');
        overlay.className = 'overlay';
        document.body.appendChild(overlay);
        overlay.style.display = 'block';
    });

    // Handle close report dialog
    document.querySelector('.close-report').addEventListener('click', closeReportDialog);

    // Handle submit report
    document.querySelector('.submit-report').addEventListener('click', () => {
        const reason = reportDialog.querySelector('textarea').value.trim();
        if (reason) {
            // Send report to server
            socket.emit('submit_report', {
                reportedUser: reportedUsername,
                reason: reason,
                reportedBy: currentUser
            });
            
            // Clear and close dialog
            reportDialog.querySelector('textarea').value = '';
            closeReportDialog();
            
            // Show success message
            alert('Report submitted successfully');
        } else {
            alert('Please provide a reason for reporting');
        }
    });

    function closeReportDialog() {
        reportDialog.style.display = 'none';
        document.querySelector('.overlay')?.remove();
        reportDialog.querySelector('textarea').value = '';
    }

    // Private Messaging
    // Chicken Chat
    const chickenMascot = document.querySelector('.duck-mascot img');
    const chickenChat = document.querySelector('.chicken-chat');
    const chickenTemplate = document.querySelector('#chicken-dialog-template');
    let chickenDialog = null;

    // Make the chicken image clickable
    chickenMascot.style.cursor = 'pointer';

    chickenMascot?.addEventListener('click', () => {
        if (!chickenDialog) {
            const template = chickenTemplate.content.cloneNode(true);
            chickenDialog = template.querySelector('.chicken-dialog');
            chickenChat.appendChild(chickenDialog);
            
            // Make the dialog draggable
            makeDraggable(chickenDialog);
            
            // Handle close button
            chickenDialog.querySelector('.chicken-close').addEventListener('click', () => {
                chickenDialog.remove();
                chickenDialog = null;
            });
            
            // Handle send button and input
            const input = chickenDialog.querySelector('.chicken-input input');
            const sendBtn = chickenDialog.querySelector('.chicken-input button');
            
            const sendMessage = () => {
                const message = input.value.trim();
                if (message) {
                    const messagesContainer = chickenDialog.querySelector('.chicken-messages');
                    const messageElement = document.createElement('div');
                    messageElement.className = 'message';
                    messageElement.innerHTML = `<span class="user">You:</span> ${message}`;
                    messagesContainer.appendChild(messageElement);
                    
                    // Add chicken's response
                    setTimeout(() => {
                        const chickenResponse = document.createElement('div');
                        chickenResponse.className = 'message chicken';
                        chickenResponse.innerHTML = `<span class="user">Chicken:</span> Bawk bawk! 🐔`;
                        messagesContainer.appendChild(chickenResponse);
                        messagesContainer.scrollTop = messagesContainer.scrollHeight;
                    }, 1000);
                    
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                    input.value = '';
                    input.focus();
                }
            };
            
            sendBtn.addEventListener('click', () => sendMessage());
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });
        }
        
        chickenDialog.style.display = 'flex';
    });

    // Private Messaging
    const dialogsContainer = document.querySelector('.pm-dialogs');
    const dialogTemplate = document.querySelector('#pm-dialog-template');

    // Create new chat window
    function createChatWindow(username) {
        const chatWindow = dialogTemplate.content.cloneNode(true).querySelector('.pm-dialog');
        chatWindow.id = `pm-${username}`;
        chatWindow.querySelector('.pm-user').textContent = username;
        
        // Position the window with offset based on existing windows
        const offset = activeChats.size * 20;
        chatWindow.style.right = `${270 + offset}px`;
        chatWindow.style.bottom = `${20 + offset}px`;

        // Make the window draggable
        makeDraggable(chatWindow);
        
        // Add close button handler
        chatWindow.querySelector('.pm-close').addEventListener('click', () => {
            chatWindow.remove();
            activeChats.delete(username);
        });

        // Add message input handler
        const input = chatWindow.querySelector('.pm-input input');
        const sendBtn = chatWindow.querySelector('.pm-input button');

        // Function to append message to chat window
        chatWindow.appendMessage = (sender, message) => {
            const messageDiv = document.createElement('div');
            messageDiv.className = `pm-message ${sender === currentUser ? 'sent' : 'received'}`;
            
            // Create a text node to safely display the message
            messageDiv.textContent = message;
            
            const messagesContainer = chatWindow.querySelector('.pm-messages');
            messagesContainer.appendChild(messageDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        };

        sendBtn.addEventListener('click', async () => {
            const message = input.value.trim();
            if (message) {
                try {
                    const encryptedMessage = await encryptMessage(message, username);
                    socket.emit('private_message', { 
                        recipient: username, 
                        sender: currentUser,
                        message: encryptedMessage, 
                        encrypted: true 
                    });
                    chatWindow.appendMessage(currentUser, message);
                    input.value = '';
                } catch (error) {
                    console.error('Failed to send encrypted message:', error);
                    alert('Failed to send encrypted message');
                }
            }
        });

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendBtn.click();
            }
        });

        return chatWindow;
    }

    // Make an element draggable
    function makeDraggable(element) {
        const header = element.querySelector('.pm-header, .chicken-header');
        let isDragging = false;
        let currentX;
        let currentY;
        let initialX;
        let initialY;
        let xOffset = 0;
        let yOffset = 0;

        if (!header) return; // Exit if no valid header found

        header.addEventListener('mousedown', dragStart);
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', dragEnd);

        function dragStart(e) {
            initialX = e.clientX - xOffset;
            initialY = e.clientY - yOffset;

            if (e.target === header) {
                isDragging = true;
                header.style.cursor = 'grabbing';
            }
        }

        function drag(e) {
            if (isDragging) {
                e.preventDefault();
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;

                xOffset = currentX;
                yOffset = currentY;

                setTranslate(currentX, currentY, element);
            }
        }

        function dragEnd(e) {
            initialX = currentX;
            initialY = currentY;
            isDragging = false;
            header.style.cursor = 'grab';
        }

        function setTranslate(xPos, yPos, el) {
            el.style.transform = `translate3d(${xPos}px, ${yPos}px, 0)`;
        }
    }

    // Load chat history
    async function loadChatHistory(user1, user2, chatWindow) {
        try {
            const response = await fetch(`/api/messages/${user1}/${user2}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const history = await response.json();
            
            const messagesContainer = chatWindow.querySelector('.pm-messages');
            messagesContainer.innerHTML = ''; // Clear existing messages
            
            history.forEach(msg => {
                const messageDiv = document.createElement('div');
                messageDiv.className = `pm-message ${msg.sender === currentUser ? 'sent' : 'received'}`;
                messageDiv.textContent = msg.message;
                messagesContainer.appendChild(messageDiv);
            });
            
            // Scroll to bottom after loading history
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        } catch (error) {
            console.error('Error loading chat history:', error);
        }
    }

    // Handle member click to open PM
    // Dynamically fetch and populate group members
function updateGroupMembers() {
    fetch('/api/group_members')
        .then(response => response.json())
        .then(members => {
            const memberList = document.querySelector('.member-list');
            // Clear existing members
            memberList.innerHTML = '';
            
            // Add new members
            members.forEach(member => {
                const memberDiv = document.createElement('div');
                memberDiv.className = member.is_current_user ? 'member self' : 'member';
                memberDiv.setAttribute('data-username', member.username);
                memberDiv.textContent = member.is_current_user ? `${member.username} (You)` : member.username;
                
                // Add click event for private messaging
                memberDiv.addEventListener('click', async () => {
                    const username = memberDiv.getAttribute('data-username');
                    
                    // Don't open chat with self
                    if (username === currentUser) return;
                    
                    // Prevent duplicate chat windows
                    if (activeChats.has(username)) {
                        // If chat window already exists, just focus it
                        const existingChatWindow = document.getElementById(`pm-${username}`);
                        if (existingChatWindow) {
                            existingChatWindow.style.display = 'flex';
                            return;
                        }
                    }
                    
                    // Create chat window
                    const chatWindow = createChatWindow(username);
                    dialogsContainer.appendChild(chatWindow);
                    activeChats.set(username, chatWindow);
                    
                    // Show the chat window
                    chatWindow.style.display = 'flex';
                    
                    // Load chat history
                    await loadChatHistory(currentUser, username, chatWindow);
                });
                
                memberList.appendChild(memberDiv);
            });
        })
        .catch(error => {
            console.error('Error fetching group members:', error);
        });
}

// Call on page load
updateGroupMembers();

// Populate task assignee dropdown
function populateTaskAssigneeDropdown() {
    fetch('/api/group_members')
        .then(response => response.json())
        .then(members => {
            const taskAssigneeSelect = document.getElementById('task-assignee');
            
            // Clear existing options (except the first 'Unassigned' option)
            while (taskAssigneeSelect.options.length > 1) {
                taskAssigneeSelect.remove(1);
            }
            
            // Add members to the dropdown
            members.forEach(member => {
                const option = document.createElement('option');
                option.value = member.username;
                option.textContent = member.username;
                
                // Highlight current user's name
                if (member.is_current_user) {
                    option.textContent += ' (You)';
                }
                
                taskAssigneeSelect.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error fetching group members for task assignee:', error);
        });
}

// Call on page load
populateTaskAssigneeDropdown();

    // Scroll to bottom of messages
    function scrollMessagesToBottom() {
        const messagesDiv = document.querySelector('.messages');
        // Use requestAnimationFrame to ensure DOM is updated before scrolling
        requestAnimationFrame(() => {
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        });
    }

    // Load previous group messages
    function loadGroupMessages() {
        fetch('/api/group_messages')
            .then(response => response.json())
            .then(messages => {
                const messagesDiv = document.querySelector('.messages');
                messagesDiv.innerHTML = ''; // Clear existing messages
                
                messages.forEach(msg => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message';
                    messageDiv.innerHTML = `
                        <span class="user">${msg.sender === currentUser ? `${msg.sender} (You)` : msg.sender}:</span> 
                        ${msg.message}
                    `;
                    messagesDiv.appendChild(messageDiv);
                });
                
                // Scroll to bottom
                scrollMessagesToBottom();
            })
            .catch(error => {
                console.error('Error loading group messages:', error);
            });
    }
    
    // Add socket listener for new group messages
    socket.on('group_message', (data) => {
        const messagesDiv = document.querySelector('.messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        messageDiv.innerHTML = `
            <span class="user">${data.sender === currentUser ? `${data.sender} (You)` : data.sender}:</span> 
            ${data.message}
        `;
        messagesDiv.appendChild(messageDiv);
        scrollMessagesToBottom();
    });
    
    // Load messages on page load
    loadGroupMessages();

    // Listen for private messages
    socket.on('private_message', async (data) => {
        const { sender, message, encrypted } = data;
        
        // Don't process our own messages
        if (sender === currentUser) return;
        
        let chatWindow = activeChats.get(sender);
        if (!chatWindow) {
            // If chat window doesn't exist, create it
            chatWindow = createChatWindow(sender);
            dialogsContainer.appendChild(chatWindow);
            activeChats.set(sender, chatWindow);
            chatWindow.style.display = 'flex';
            
            // Load chat history
            loadChatHistory(currentUser, sender, chatWindow);
        }
        
        try {
            let displayMessage;
            if (encrypted) {
                console.log('Received encrypted message:', message);
                displayMessage = await decryptMessage(message, currentUser);
                console.log('Decrypted message:', displayMessage);
            } else {
                displayMessage = message;
            }
            chatWindow.appendMessage(sender, displayMessage);
        } catch (error) {
            console.error('Failed to decrypt message:', error);
            chatWindow.appendMessage(sender, '[Encrypted message - decryption failed]');
        }
    });

    // Calendar functionality
    const calendar = {
        currentDate: new Date(),
        selectedDates: new Map(), // date string -> status (available, unavailable, meeting)

        init() {
            this.updateCalendar();
            this.attachEventListeners();
        },

        updateCalendar() {
            const year = this.currentDate.getFullYear();
            const month = this.currentDate.getMonth();
            
            // Update month display
            document.querySelector('.current-month').textContent = 
                this.currentDate.toLocaleString('default', { month: 'long', year: 'numeric' });

            const firstDay = new Date(year, month, 1);
            const lastDay = new Date(year, month + 1, 0);
            const startingDay = firstDay.getDay();
            const totalDays = lastDay.getDate();

            // Get calendar grid
            const calendarGrid = document.querySelector('.calendar-grid');
            calendarGrid.innerHTML = '';

            // Add days from previous month
            const prevMonthDays = new Date(year, month, 0).getDate();
            for (let i = startingDay - 1; i >= 0; i--) {
                const day = prevMonthDays - i;
                const dayElement = this.createDayElement(day, 'other-month');
                calendarGrid.appendChild(dayElement);
            }

            // Add days of current month
            const today = new Date();
            for (let day = 1; day <= totalDays; day++) {
                const isToday = today.getDate() === day && 
                              today.getMonth() === month && 
                              today.getFullYear() === year;
                
                const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
                const status = this.selectedDates.get(dateStr);
                
                const dayElement = this.createDayElement(day, isToday ? 'today' : '', status);
                calendarGrid.appendChild(dayElement);
            }

            // Add days from next month
            const remainingSlots = 42 - (startingDay + totalDays); // 42 = 6 rows × 7 days
            for (let day = 1; day <= remainingSlots; day++) {
                const dayElement = this.createDayElement(day, 'other-month');
                calendarGrid.appendChild(dayElement);
            }
        },

        createDayElement(day, extraClass = '', status = null) {
            const dayElement = document.createElement('div');
            dayElement.className = `calendar-day ${extraClass} ${status || ''}`;
            dayElement.textContent = day;

            if (!extraClass.includes('other-month')) {
                dayElement.addEventListener('click', () => this.toggleAvailability(dayElement));
            }

            return dayElement;
        },

        toggleAvailability(dayElement) {
            const currentStatus = this.getStatus(dayElement);
            const newStatus = this.getNextStatus(currentStatus);
            
            // Remove all status classes
            dayElement.classList.remove('available', 'unavailable', 'meeting');
            
            if (newStatus) {
                dayElement.classList.add(newStatus);
                
                // Store the selection
                const dateStr = this.getDateString(dayElement);
                this.selectedDates.set(dateStr, newStatus);
            } else {
                // If cycling back to no status, remove from selections
                const dateStr = this.getDateString(dayElement);
                this.selectedDates.delete(dateStr);
            }
        },

        getStatus(dayElement) {
            if (dayElement.classList.contains('available')) return 'available';
            if (dayElement.classList.contains('unavailable')) return 'unavailable';
            if (dayElement.classList.contains('meeting')) return 'meeting';
            return null;
        },

        getNextStatus(currentStatus) {
            const statusCycle = [null, 'available', 'unavailable', 'meeting'];
            const currentIndex = statusCycle.indexOf(currentStatus);
            return statusCycle[(currentIndex + 1) % statusCycle.length];
        },

        getDateString(dayElement) {
            const day = dayElement.textContent.padStart(2, '0');
            const month = String(this.currentDate.getMonth() + 1).padStart(2, '0');
            const year = this.currentDate.getFullYear();
            return `${year}-${month}-${day}`;
        },

        attachEventListeners() {
            document.querySelector('.prev-month').addEventListener('click', () => {
                this.currentDate.setMonth(this.currentDate.getMonth() - 1);
                this.updateCalendar();
            });

            document.querySelector('.next-month').addEventListener('click', () => {
                this.currentDate.setMonth(this.currentDate.getMonth() + 1);
                this.updateCalendar();
            });
        }
    };

    // Initialize calendar when on schedule page
    const schedulePage = document.getElementById('schedule');
    if (schedulePage) {
        calendar.init();
    }
});
