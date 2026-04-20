import { pgTable, serial, text, integer, boolean, timestamp, jsonb, varchar, decimal, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").unique(),
  password: text("password"),
  phone: text("phone"),
  profileImageUrl: text("profile_image_url"),
  bio: text("bio"),
  credits: integer("credits").default(100),
  bonusCredits: integer("bonus_credits").default(50),
  isVerified: boolean("is_verified").default(false),
  isCreator: boolean("is_creator").default(false),
  isAdmin: boolean("is_admin").default(false),
  tier: text("tier").default("free"),
  followersCount: integer("followers_count").default(0),
  followingCount: integer("following_count").default(0),
  totalEarnings: decimal("total_earnings", { precision: 10, scale: 2 }).default("0"),
  provider: text("provider").default("local"),
  googleId: text("google_id").unique(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const sessions = pgTable("sessions", {
  sid: varchar("sid", { length: 255 }).primaryKey(),
  sess: jsonb("sess").notNull(),
  expire: timestamp("expire").notNull(),
});

export const videos = pgTable("videos", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  title: text("title"),
  description: text("description"),
  videoUrl: text("video_url").notNull(),
  thumbnailUrl: text("thumbnail_url"),
  duration: integer("duration"),
  views: integer("views").default(0),
  likes: integer("likes").default(0),
  comments: integer("comments").default(0),
  shares: integer("shares").default(0),
  isPublic: boolean("is_public").default(true),
  isPremium: boolean("is_premium").default(false),
  premiumPrice: integer("premium_price"),
  category: text("category"),
  tags: text("tags").array(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const videoLikes = pgTable("video_likes", {
  id: serial("id").primaryKey(),
  videoId: integer("video_id").references(() => videos.id),
  userId: integer("user_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
});

export const videoComments = pgTable("video_comments", {
  id: serial("id").primaryKey(),
  videoId: integer("video_id").references(() => videos.id),
  userId: integer("user_id").references(() => users.id),
  content: text("content").notNull(),
  likes: integer("likes").default(0),
  createdAt: timestamp("created_at").defaultNow(),
});

export const videoViews = pgTable("video_views", {
  id: serial("id").primaryKey(),
  videoId: integer("video_id").references(() => videos.id),
  userId: integer("user_id").references(() => users.id),
  watchTime: integer("watch_time"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const follows = pgTable("follows", {
  id: serial("id").primaryKey(),
  followerId: integer("follower_id").references(() => users.id),
  followingId: integer("following_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
});

export const conversations = pgTable("conversations", {
  id: serial("id").primaryKey(),
  user1Id: integer("user1_id").references(() => users.id),
  user2Id: integer("user2_id").references(() => users.id),
  lastMessageAt: timestamp("last_message_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  conversationId: integer("conversation_id").references(() => conversations.id),
  senderId: integer("sender_id").references(() => users.id),
  content: text("content"),
  messageType: text("message_type").default("text"),
  mediaUrl: text("media_url"),
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  type: text("type").notNull(),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  credits: integer("credits"),
  status: text("status").default("pending"),
  paymentMethod: text("payment_method"),
  paymentId: text("payment_id"),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const subscriptions = pgTable("subscriptions", {
  id: serial("id").primaryKey(),
  subscriberId: integer("subscriber_id").references(() => users.id),
  creatorId: integer("creator_id").references(() => users.id),
  tier: text("tier").default("basic"),
  price: decimal("price", { precision: 10, scale: 2 }),
  status: text("status").default("active"),
  startDate: timestamp("start_date").defaultNow(),
  endDate: timestamp("end_date"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const virtualGifts = pgTable("virtual_gifts", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  iconUrl: text("icon_url"),
  animationUrl: text("animation_url"),
  credits: integer("credits").notNull(),
  category: text("category"),
  isActive: boolean("is_active").default(true),
});

export const giftTransactions = pgTable("gift_transactions", {
  id: serial("id").primaryKey(),
  senderId: integer("sender_id").references(() => users.id),
  receiverId: integer("receiver_id").references(() => users.id),
  giftId: integer("gift_id").references(() => virtualGifts.id),
  videoId: integer("video_id").references(() => videos.id),
  credits: integer("credits").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const loveProfiles = pgTable("love_profiles", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).unique(),
  displayName: text("display_name"),
  age: integer("age"),
  gender: text("gender"),
  lookingFor: text("looking_for"),
  bio: text("bio"),
  photos: text("photos").array(),
  interests: text("interests").array(),
  location: text("location"),
  isActive: boolean("is_active").default(true),
  boostExpiry: timestamp("boost_expiry"),
  swipesRemaining: integer("swipes_remaining").default(5),
  createdAt: timestamp("created_at").defaultNow(),
});

export const loveSwipes = pgTable("love_swipes", {
  id: serial("id").primaryKey(),
  swiperId: integer("swiper_id").references(() => users.id),
  targetId: integer("target_id").references(() => users.id),
  direction: text("direction").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const loveMatches = pgTable("love_matches", {
  id: serial("id").primaryKey(),
  user1Id: integer("user1_id").references(() => users.id),
  user2Id: integer("user2_id").references(() => users.id),
  compatibilityScore: integer("compatibility_score"),
  isUnlocked: boolean("is_unlocked").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const creatorProfiles = pgTable("creator_profiles", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).unique(),
  displayName: text("display_name"),
  category: text("category"),
  subscriptionPrice: decimal("subscription_price", { precision: 10, scale: 2 }),
  totalEarnings: decimal("total_earnings", { precision: 10, scale: 2 }).default("0"),
  subscriberCount: integer("subscriber_count").default(0),
  isVerified: boolean("is_verified").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const withdrawalRequests = pgTable("withdrawal_requests", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  paymentMethod: text("payment_method").notNull(),
  paymentDetails: jsonb("payment_details"),
  status: text("status").default("pending"),
  processedAt: timestamp("processed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const plugins = pgTable("plugins", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  category: text("category"),
  price: decimal("price", { precision: 10, scale: 2 }),
  iconUrl: text("icon_url"),
  authorId: integer("author_id").references(() => users.id),
  downloads: integer("downloads").default(0),
  rating: decimal("rating", { precision: 3, scale: 2 }),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const pluginInstalls = pgTable("plugin_installs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  pluginId: integer("plugin_id").references(() => plugins.id),
  installedAt: timestamp("installed_at").defaultNow(),
});

export const contentFlags = pgTable("content_flags", {
  id: serial("id").primaryKey(),
  videoId: integer("video_id").references(() => videos.id),
  reporterId: integer("reporter_id").references(() => users.id),
  reason: text("reason").notNull(),
  status: text("status").default("pending"),
  reviewedBy: integer("reviewed_by").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
});

export const userStrikes = pgTable("user_strikes", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  reason: text("reason").notNull(),
  severity: text("severity").default("warning"),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).omit({ id: true, createdAt: true, updatedAt: true });
export const insertVideoSchema = createInsertSchema(videos).omit({ id: true, createdAt: true });
export const insertMessageSchema = createInsertSchema(messages).omit({ id: true, createdAt: true });
export const insertTransactionSchema = createInsertSchema(transactions).omit({ id: true, createdAt: true });
export const insertSubscriptionSchema = createInsertSchema(subscriptions).omit({ id: true, createdAt: true });
export const insertLoveProfileSchema = createInsertSchema(loveProfiles).omit({ id: true, createdAt: true });

export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Video = typeof videos.$inferSelect;
export type InsertVideo = z.infer<typeof insertVideoSchema>;
export type Message = typeof messages.$inferSelect;
export type InsertMessage = z.infer<typeof insertMessageSchema>;
export type Transaction = typeof transactions.$inferSelect;
export type InsertTransaction = z.infer<typeof insertTransactionSchema>;
export type Subscription = typeof subscriptions.$inferSelect;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type Conversation = typeof conversations.$inferSelect;
export type LoveProfile = typeof loveProfiles.$inferSelect;
export type InsertLoveProfile = z.infer<typeof insertLoveProfileSchema>;
