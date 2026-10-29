package dev.yuiop.offlinecrypt.mixin;

import com.llamalad7.mixinextras.injector.v2.WrapWithCondition;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.login.ClientboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.slf4j.Logger;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Cifra la connessione dei giocatori che entrerebbero senza cifratura.
 *
 * <p>Il server vanilla cifra solo insieme al login Mojang. In offline-mode, oppure per chi EasyAuth
 * fa entrare come non premium, la connessione resta in chiaro: chat, /login e chiave della voice chat.
 * Dal 1.20.5 la richiesta di cifratura ha il campo "shouldAuthenticate": se e' false il client cifra
 * senza contattare Mojang. Qui la si manda a chi arriva a VERIFYING con la connessione ancora in chiaro,
 * cioe' dopo che vanilla o EasyAuth hanno gia' deciso il profilo: chi decide chi entra non cambia.
 */
@Mixin(ServerLoginPacketListenerImpl.class)
public abstract class ServerLoginPacketListenerImplMixin {
	@Unique
	private static final Logger offlinecrypt$LOGGER = LogUtils.getLogger();

	@Shadow
	@Final
	private byte[] challenge;
	@Shadow
	@Final
	MinecraftServer server;
	@Shadow
	@Final
	Connection connection;
	@Shadow
	private volatile ServerLoginPacketListenerImpl.State state;
	@Shadow
	String requestedUsername;

	// Vero tra la nostra richiesta di cifratura e la risposta del client.
	@Unique
	private volatile boolean offlinecrypt$inAttesa;

	@Inject(method = "tick", at = @At("HEAD"))
	private void offlinecrypt$chiediCifratura(CallbackInfo ci) {
		if (this.state != ServerLoginPacketListenerImpl.State.VERIFYING
				|| this.connection.isEncrypted()
				|| this.connection.isMemoryConnection()
				|| this.offlinecrypt$inAttesa) {
			return;
		}

		// Il profilo scelto resta in authenticatedProfile: dopo la cifratura si torna a VERIFYING e il login prosegue.
		this.offlinecrypt$inAttesa = true;
		this.state = ServerLoginPacketListenerImpl.State.KEY;
		this.connection.send(new ClientboundHelloPacket(
				"", this.server.getKeyPair().getPublic().getEncoded(), this.challenge, false));
		offlinecrypt$LOGGER.info("[Cifratura Offline] {}: chiedo la cifratura senza login Mojang", this.requestedUsername);
	}

	// handleKey vanilla controlla la sfida e attiva la cifratura (Krypton ci aggancia la sua versione nativa),
	// poi avvierebbe il thread che chiede a Mojang se il giocatore e' autentico: per le nostre richieste lo salta.
	@WrapWithCondition(method = "handleKey", at = @At(value = "INVOKE", target = "Ljava/lang/Thread;start()V"))
	private boolean offlinecrypt$saltaLoginMojang(Thread thread) {
		if (!this.offlinecrypt$inAttesa) {
			return true;
		}

		this.offlinecrypt$inAttesa = false;
		this.state = ServerLoginPacketListenerImpl.State.VERIFYING;
		offlinecrypt$LOGGER.info("[Cifratura Offline] {}: connessione cifrata", this.requestedUsername);
		return false;
	}
}
