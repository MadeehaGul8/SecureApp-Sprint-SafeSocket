"use strict";

const { Kafka, Partitioners } = require('kafkajs');

// ── Kafka client config ───────────────────────────────────
const kafka = new Kafka({
    clientId: 'safesocket',
    brokers:  [process.env.KAFKA_BROKER || 'localhost:9092'],
    retry: {
        initialRetryTime: 300,
        retries: 3
    }
});

const producer = kafka.producer({
    createPartitioner: Partitioners.LegacyPartitioner
});
const consumer = kafka.consumer({ groupId: 'safesocket-group' });

let isConnected = false;

// ══════════════════════════════════════════════════════════
// CONNECT — producer + consumer
// ══════════════════════════════════════════════════════════
async function connect() {
    try {
        await producer.connect();
        await consumer.connect();
        await consumer.subscribe({
            topic:         'chat-messages',
            fromBeginning: false
        });
        isConnected = true;
        console.log('[KAFKA] ✅ Connected to broker');
    } catch (err) {
        isConnected = false;
        console.warn('[KAFKA] ⚠️  Broker unavailable — running without Kafka');
        console.warn('[KAFKA] Start Kafka or set KAFKA_BROKER in .env');
    }
}

// ══════════════════════════════════════════════════════════
// PUBLISH — send message to Kafka topic
// ══════════════════════════════════════════════════════════
async function publishMessage(room, from, message, type = 'public') {
    if (!isConnected) return false;

    try {
        await producer.send({
            topic: 'chat-messages',
            messages: [{
                key:   room,
                value: JSON.stringify({
                    room,
                    from,
                    message,
                    type,
                    timestamp: new Date().toISOString()
                })
            }]
        });
        return true;
    } catch (err) {
        console.error('[KAFKA] Publish error:', err.message);
        return false;
    }
}

// ══════════════════════════════════════════════════════════
// CONSUME — receive messages and broadcast via Socket.IO
// ══════════════════════════════════════════════════════════
async function startConsumer(io) {
    if (!isConnected) return;

    await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
            try {
                const data = JSON.parse(message.value.toString());
                console.log(`[KAFKA] Message received: ${data.from} → ${data.room}`);

                if (data.type === 'private') {
                    // Private messages handled separately
                    return;
                }

                // Broadcast to room via Socket.IO
                io.to(data.room).emit('receive_message', {
                    from:      data.from,
                    message:   data.message,
                    timestamp: data.timestamp,
                    via:       'kafka'
                });

            } catch (err) {
                console.error('[KAFKA] Message parse error:', err.message);
            }
        }
    });

    console.log('[KAFKA] ✅ Consumer running on topic: chat-messages');
}

// ══════════════════════════════════════════════════════════
// STATUS — check if Kafka is connected
// ══════════════════════════════════════════════════════════
function getStatus() {
    return {
        connected: isConnected,
        broker:    process.env.KAFKA_BROKER || 'localhost:9092',
        topic:     'chat-messages',
        groupId:   'safesocket-group'
    };
}

// ══════════════════════════════════════════════════════════
// DISCONNECT — clean shutdown
// ══════════════════════════════════════════════════════════
async function disconnect() {
    if (isConnected) {
        await producer.disconnect();
        await consumer.disconnect();
        isConnected = false;
        console.log('[KAFKA] Disconnected');
    }
}

module.exports = { connect, publishMessage, startConsumer, getStatus, disconnect };